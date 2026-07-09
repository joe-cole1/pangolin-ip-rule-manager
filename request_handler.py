import hmac
import html
import ipaddress
import json
import os
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def _format_retention(minutes: int) -> str:
    if minutes >= 1440 and minutes % 1440 == 0:
        days = minutes // 1440
        return f"{days} day" if days == 1 else f"{days} days"
    if minutes >= 60 and minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"


def _load_template(name: str, tokens: dict[str, str]) -> str:
    with open(os.path.join(_TEMPLATE_DIR, name), encoding="utf-8") as f:
        content = f.read()
    for key, value in tokens.items():
        content = content.replace("{{" + key + "}}", value)
    return content


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
        protocol = "https" if ssl else "http"
        raw_url = f"{protocol}://{domain}"
        safe_url = html.escape(raw_url, quote=True)
        safe_name = html.escape(name)
        rows.append(
            '      <a class="access-link" href="'
            + safe_url
            + '" target="_blank" rel="noopener noreferrer">\n'
            '        <span class="access-link-left">\n'
            '          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;">'
            '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>'
            '<polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>'
            "</svg>\n"
            '          <span class="access-link-text">\n'
            f'            <span class="access-link-label">Open {safe_name}</span>\n'
            f'            <span class="access-link-url">{safe_url}</span>\n'
            "          </span>\n"
            "        </span>\n"
            '        <svg class="access-link-arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
            '<line x1="5" y1="12" x2="19" y2="12"/>'
            '<polyline points="12 5 19 12 12 19"/>'
            "</svg>\n"
            "      </a>"
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
    except Exception:
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

    details_label = "Technical details" if overall_ok else "What went wrong?"

    # Only show individual allowed resources if not redirecting successfully
    show_individual_resources = not (redirect_to_launcher and success)
    resource_rows = ""
    if show_individual_resources:
        resource_rows = _render_resource_rows(resources or [], overall_ok)

    # Build the redirection banner and inline script if redirecting on success
    redirect_banner_html = ""
    if (
        success
        and redirect_to_launcher
        and dashboard_url
        and redirect_delay_seconds > 0
    ):
        safe_url = html.escape(dashboard_url, quote=True)
        redirect_banner_html = (
            f'      <div class="redirect-banner" style="background: var(--accent-hover-bg); border: 1px solid var(--accent); padding: 12px 16px; border-radius: calc(var(--radius) - 2px); margin-bottom: 12px; font-size: 13px; text-align: center; color: var(--text);">\n'
            f'        Redirecting to Resource Launcher in <strong id="countdown">{redirect_delay_seconds}</strong> seconds...\n'
            "      </div>\n"
            "      <script>\n"
            "        (function() {\n"
            f"          var delay = {redirect_delay_seconds};\n"
            f'          var url = "{safe_url}";\n'
            "          var interval = setInterval(function() {\n"
            "            delay--;\n"
            '            var el = document.getElementById("countdown");\n'
            "            if (el) el.innerText = delay;\n"
            "            if (delay <= 0) {\n"
            "              clearInterval(interval);\n"
            "              window.location.href = url;\n"
            "            }\n"
            "          }, 1000);\n"
            "        })();\n"
            "      </script>"
        )

    # Build the central launcher button if dashboard_url is set and overall_ok is True
    launcher_row = ""
    if overall_ok and dashboard_url:
        safe_url = html.escape(dashboard_url, quote=True)
        launcher_row = (
            f'      <a class="access-link launcher-link" href="{safe_url}" target="_blank" rel="noopener noreferrer" style="border-color: var(--accent); background: var(--accent-hover-bg); margin-bottom: 8px;">\n'
            '        <span class="access-link-left">\n'
            '          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0; color: var(--accent);">'
            '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'
            '<polyline points="9 22 9 12 15 12 15 22"/>'
            "</svg>\n"
            '          <span class="access-link-text">\n'
            '            <span class="access-link-label" style="font-weight:600;">Open Resource Launcher</span>\n'
            f'            <span class="access-link-url" style="color: var(--text); opacity: 0.85;">{safe_url}</span>\n'
            "          </span>\n"
            "        </span>\n"
            '        <svg class="access-link-arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--accent);">'
            '<line x1="5" y1="12" x2="19" y2="12"/>'
            '<polyline points="12 5 19 12 12 19"/>'
            "</svg>\n"
            "      </a>"
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
        (
            '  <button class="bookmark-btn" onclick="bookmarkPage()">\n'
            '    <span class="access-link-left">\n'
            '      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;">'
            '<path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/>'
            "</svg>\n"
            '      <span class="access-link-text">\n'
            '        <span class="access-link-label">Bookmark this page</span>\n'
            '        <span class="access-link-url">Save for one-tap access next time</span>\n'
            "      </span>\n"
            "    </span>\n"
            '    <svg class="access-link-arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
            '<line x1="5" y1="12" x2="19" y2="12"/>'
            '<polyline points="12 5 19 12 12 19"/>'
            "</svg>\n"
            "  </button>"
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

    return _load_template(
        "checkin.html",
        {
            "DOT_CLASS": dot_class,
            "SITE_NAME_SUB": site_name_sub,
            "HERO": hero,
            "IP": ip,
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
            "DETAILS_IP": ip,
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


def create_image_request_handler(ctx: dict):
    """
    Factory that returns an ImageRequestHandler class bound to the provided context.
    Expected ctx keys:
      - update_enabled: bool
      - retention_minutes: int
      - crowdsec_enabled: bool
      - state: dict
      - state_lock: threading.Lock
      - now_utc_iso: callable () -> str
      - save_state: callable () -> None
      - add_ip_to_targets: callable (ip: str) -> dict
      - banner_png: bytes
      - banner_gif: bytes
      - redact_headers_for_log: callable (headers: dict[str, str]) -> dict[str, str]
      - site_name: str
      - proxy_shared_secret: str (optional; when set, X-Proxy-Secret must match)
    """

    class ImageRequestHandler(BaseHTTPRequestHandler):
        server_version = "BannerServer/1.0"

        def log_message(self, fmt, *args):
            print("[http]", self.address_string(), "-", fmt % args)

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
                            f"[warn] Rejected non-global IP from header: {raw.strip()!r}"
                        )
                        return None
                    return str(ip_obj)
                except ValueError:
                    print(
                        f"[warn] Rejected unparseable IP from header: {raw.strip()!r}"
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
            """Defense-in-depth gate. When PROXY_SHARED_SECRET is configured, the
            upstream proxy must inject a matching X-Proxy-Secret header. Compared with
            hmac.compare_digest to avoid timing leaks. Returns True when no secret is
            configured (feature disabled) or the provided secret matches."""
            expected = ctx.get("proxy_shared_secret", "")
            if not expected:
                return True
            provided = self.headers.get("X-Proxy-Secret", "")
            return hmac.compare_digest(provided, expected)

        def _send_security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            # All CSS/JS is inline and self-contained (no external fetches), so a
            # restrictive policy is possible. 'unsafe-inline' is still required for
            # the inline <style>/<script> blocks; everything else is locked down.
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; "
                "img-src 'self' data:; "
                "style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; "
                "base-uri 'none'; "
                "form-action 'none'; "
                "frame-ancestors 'none'",
            )

        def _send_html(self, status: int, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(encoded)

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
                self.end_headers()
                self.wfile.write(b"ok")
                return

            # Browsers request /favicon.ico automatically after loading the check-in
            # page. Answer with an empty 204 before the .png/.gif routing so it does
            # not land in the invalid-path error branch and pollute the logs. Touches
            # no state and makes no upstream calls.
            if path.lower() == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return

            # Defense-in-depth: reject anything that did not transit the proxy before
            # touching state or the Pangolin/CrowdSec APIs. Bare 403, no body detail.
            if not self._proxy_secret_ok():
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden")
                print(
                    f"[error] Rejected request with missing/invalid X-Proxy-Secret: {self.path}"
                )
                return

            ip = self._get_real_ip()
            remote_user = self.headers.get("Remote-User", "")

            print(f"New request from {ip}  user: {remote_user}  path: {path}")

            if ctx.get("debug_log_headers"):
                redact = ctx.get("redact_headers_for_log")
                if redact:
                    print("[http] headers:", redact(dict(self.headers)))

            lower_path = path.lower()

            # /update?ip=1.2.3.4 endpoint (guarded by UPDATE_ENDPOINT_ENABLED)
            if lower_path == "/update":
                if not ctx.get("update_enabled"):
                    # Intentionally bare — do not reveal the endpoint exists
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not found")
                    print(f"[error] Update endpoint disabled: {self.path}")
                    return

                qs = parse_qs(parsed_path.query or "")
                raw_ip = (qs.get("ip", [""])[0] or "").strip()
                if not raw_ip:
                    print(f"[error] Missing 'ip' query parameter: {self.path}")
                    self._send_html(
                        400,
                        _build_error_html(
                            "Bad request",
                            "Missing required <code>ip</code> query parameter. "
                            "Expected format: /update?ip=1.2.3.4",
                            site_name=ctx.get("site_name", ""),
                        ),
                    )
                    return

                try:
                    normalized_ip = str(ipaddress.ip_address(raw_ip))
                except Exception:
                    print(f"[error] Invalid IP address: {raw_ip}")
                    self._send_html(
                        400,
                        _build_error_html(
                            "Bad request",
                            f"&#39;{html.escape(raw_ip)}&#39; is not a valid IP address.",
                            site_name=ctx.get("site_name", ""),
                        ),
                    )
                    return

                if not ipaddress.ip_address(normalized_ip).is_global:
                    print(
                        f"[error] Rejected non-global IP in /update: {normalized_ip!r}"
                    )
                    self._send_html(
                        400,
                        _build_error_html(
                            "Bad request",
                            f"&#39;{normalized_ip}&#39; is a non-routable IP address and cannot be allowlisted.",
                            site_name=ctx.get("site_name", ""),
                        ),
                    )
                    return

                with ctx["state_lock"]:
                    rec = ctx["state"].setdefault(
                        normalized_ip,
                        {"last_seen": ctx["now_utc_iso"](), "resources": {}},
                    )
                    rec["last_seen"] = ctx["now_utc_iso"]()
                ctx["save_state"]()

                update_results = {}
                try:
                    update_results = ctx["add_ip_to_targets"](
                        normalized_ip, remote_user=remote_user
                    )
                except Exception as e:
                    print(f"[error] add_ip_to_targets failed for {normalized_ip}: {e}")
                    update_results = {
                        "pangolin": {"ok": False, "detail": str(e), "enabled": True},
                        "crowdsec": {
                            "ok": False,
                            "detail": "not reached",
                            "enabled": ctx.get("crowdsec_enabled", False),
                        },
                    }

                if self._wants_html():
                    pangolin_ok = update_results.get("pangolin", {}).get("ok", False)
                    crowdsec_ok = update_results.get("crowdsec", {}).get("ok", False)
                    crowdsec_enabled = ctx.get("crowdsec_enabled", False)
                    success = pangolin_ok and (not crowdsec_enabled or crowdsec_ok)

                    redirect_enabled = ctx.get("redirect_to_launcher", False)
                    redirect_delay = ctx.get("redirect_delay_seconds", 3)

                    if (
                        redirect_enabled
                        and success
                        and ctx.get("pangolin_dashboard_url")
                        and redirect_delay == 0
                    ):
                        self.send_response(302)
                        self.send_header("Location", ctx["pangolin_dashboard_url"])
                        self.send_header(
                            "Cache-Control",
                            "no-store, no-cache, must-revalidate, max-age=0",
                        )
                        self.send_header("Pragma", "no-cache")
                        self.send_header("Expires", "0")
                        self._send_security_headers()
                        self.end_headers()
                        return

                    self._send_html(
                        200,
                        _build_checkin_html(
                            ip=normalized_ip,
                            results=update_results,
                            retention_minutes=ctx.get("retention_minutes", 0),
                            last_seen=ctx["now_utc_iso"](),
                            crowdsec_enabled=ctx.get("crowdsec_enabled", False),
                            resources=update_results.get("resources", []),
                            site_name=ctx.get("site_name", ""),
                            dashboard_url=ctx.get("pangolin_dashboard_url", ""),
                            redirect_to_launcher=redirect_enabled,
                            redirect_delay_seconds=redirect_delay,
                        ),
                    )
                else:
                    payload = json.dumps(
                        {
                            "ok": True,
                            "ip": normalized_ip,
                            "retention_minutes": ctx.get("retention_minutes", 0),
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header(
                        "Cache-Control",
                        "no-store, no-cache, must-revalidate, max-age=0",
                    )
                    self.send_header("Pragma", "no-cache")
                    self.send_header("Expires", "0")
                    self._send_security_headers()
                    self.end_headers()
                    self.wfile.write(payload)
                return

            # Forbid root path
            if path == "/":
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden")
                print(f"[error] Root path forbidden: {self.path}")
                return

            # Only handle .png and .gif paths
            is_png = lower_path.endswith(".png")
            is_gif = lower_path.endswith(".gif")
            if not (is_png or is_gif):
                print(f"[error] Invalid path (not .png/.gif): {self.path}")
                if self._wants_html():
                    self._send_html(
                        404,
                        _build_error_html(
                            "Page not found",
                            "This URL isn&#39;t a valid check-in path. "
                            "Make sure you&#39;re using the correct link ending in .png or .gif.",
                            site_name=ctx.get("site_name", ""),
                        ),
                    )
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not found")
                return

            # Update state
            now_iso = ctx["now_utc_iso"]()
            with ctx["state_lock"]:
                rec = ctx["state"].setdefault(
                    ip, {"last_seen": now_iso, "resources": {}}
                )
                rec["last_seen"] = now_iso
            ctx["save_state"]()

            # Run checkin against all targets
            results = {}
            try:
                results = ctx["add_ip_to_targets"](ip, remote_user=remote_user)
            except Exception as e:
                print(f"[error] add_ip_to_targets failed for {ip}: {e}")
                results = {
                    "pangolin": {"ok": False, "detail": str(e), "enabled": True},
                    "crowdsec": {
                        "ok": False,
                        "detail": "not reached",
                        "enabled": ctx.get("crowdsec_enabled", False),
                    },
                }

            # Browser gets the HTML page; everything else gets the transparent image
            if self._wants_html():
                pangolin_ok = results.get("pangolin", {}).get("ok", False)
                crowdsec_ok = results.get("crowdsec", {}).get("ok", False)
                crowdsec_enabled = ctx.get("crowdsec_enabled", False)
                success = pangolin_ok and (not crowdsec_enabled or crowdsec_ok)

                redirect_enabled = ctx.get("redirect_to_launcher", False)
                redirect_delay = ctx.get("redirect_delay_seconds", 3)

                if (
                    redirect_enabled
                    and success
                    and ctx.get("pangolin_dashboard_url")
                    and redirect_delay == 0
                ):
                    self.send_response(302)
                    self.send_header("Location", ctx["pangolin_dashboard_url"])
                    self.send_header(
                        "Cache-Control",
                        "no-store, no-cache, must-revalidate, max-age=0",
                    )
                    self.send_header("Pragma", "no-cache")
                    self.send_header("Expires", "0")
                    self._send_security_headers()
                    self.end_headers()
                    return

                self._send_html(
                    200,
                    _build_checkin_html(
                        ip=ip,
                        results=results,
                        retention_minutes=ctx.get("retention_minutes", 0),
                        last_seen=now_iso,
                        crowdsec_enabled=ctx.get("crowdsec_enabled", False),
                        resources=results.get("resources", []),
                        site_name=ctx.get("site_name", ""),
                        dashboard_url=ctx.get("pangolin_dashboard_url", ""),
                        redirect_to_launcher=redirect_enabled,
                        redirect_delay_seconds=redirect_delay,
                    ),
                )
            else:
                body = ctx["banner_gif"] if is_gif else ctx["banner_png"]
                ctype = "image/gif" if is_gif else "image/png"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header(
                    "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
                )
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(body)

    return ImageRequestHandler
