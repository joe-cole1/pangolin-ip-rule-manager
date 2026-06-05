from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta, timezone
import ipaddress


def _build_checkin_html(ip: str, results: dict, retention_minutes: int, last_seen: str, crowdsec_enabled: bool) -> str:
    """Build the HTML checkin response page."""

    # Compute expiry time
    try:
        seen_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        expires_dt = seen_dt + timedelta(minutes=retention_minutes)
        expires_str = expires_dt.strftime("%Y-%m-%d %H:%M UTC")
        expires_iso = expires_dt.isoformat()
    except Exception:
        expires_str = "unknown"
        expires_iso = "unknown"

    # Overall success = pangolin ok (crowdsec is optional)
    pangolin_ok = results.get("pangolin", {}).get("ok", False)
    pangolin_detail = results.get("pangolin", {}).get("detail", "unknown")
    crowdsec_ok = results.get("crowdsec", {}).get("ok", False)
    crowdsec_detail = results.get("crowdsec", {}).get("detail", "disabled")
    overall_ok = pangolin_ok

    # Status dot and hero message
    dot_class = "status-dot" if overall_ok else "status-dot err"
    if overall_ok:
        hero = "You&#39;re all set!<br><strong>Jellyfin should work on your TV now.</strong>"
    else:
        hero = "Something went wrong.<br><strong>Jellyfin may not work right now &mdash; try again in a moment.</strong>"

    # Pangolin badge
    if pangolin_ok:
        pangolin_badge = '<span class="badge ok">Active</span>'
    else:
        pangolin_badge = '<span class="badge err">Failed</span>'

    # CrowdSec badge
    if not crowdsec_enabled:
        crowdsec_badge = '<span class="badge skip">Not enabled</span>'
    elif crowdsec_ok:
        crowdsec_badge = '<span class="badge ok">Added</span>'
    else:
        crowdsec_badge = '<span class="badge err">Failed</span>'

    # Details section
    pangolin_detail_class = "ok" if pangolin_ok else "bad"
    if crowdsec_enabled:
        crowdsec_detail_class = "ok" if crowdsec_ok else "bad"
        crowdsec_detail_display = crowdsec_detail
    else:
        crowdsec_detail_class = "val"
        crowdsec_detail_display = "disabled"

    # Details button label
    details_label = "Technical details" if overall_ok else "What went wrong?"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Check-in</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500&display=swap');

  :root {{
    --bg:        #0d0f12;
    --surface:   #151820;
    --border:    #232733;
    --border-hi: #2e3344;
    --text:      #e2e6f0;
    --muted:     #6b7390;
    --accent:    #4ade80;
    --accent-dim:#1a3d28;
    --warn:      #facc15;
    --warn-dim:  #3a3010;
    --err:       #f87171;
    --err-dim:   #3d1515;
    --mono:      'IBM Plex Mono', monospace;
    --sans:      'IBM Plex Sans', sans-serif;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-weight: 300;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 24px 16px 48px;
    background-image:
      linear-gradient(var(--border) 1px, transparent 1px),
      linear-gradient(90deg, var(--border) 1px, transparent 1px);
    background-size: 32px 32px;
    background-position: center center;
  }}

  .card {{
    width: 100%;
    max-width: 440px;
    background: var(--surface);
    border: 1px solid var(--border-hi);
    border-radius: 12px;
    overflow: hidden;
    box-shadow: 0 8px 48px rgba(0,0,0,.5);
    animation: rise .45s cubic-bezier(.22,1,.36,1) both;
  }}
  @keyframes rise {{
    from {{ opacity:0; transform: translateY(18px); }}
    to   {{ opacity:1; transform: translateY(0); }}
  }}

  .card-header {{
    padding: 20px 24px 18px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .status-dot {{
    width: 10px; height: 10px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-dim);
    flex-shrink: 0;
    animation: pulse 2.4s ease-in-out infinite;
  }}
  .status-dot.err {{ background: var(--err); box-shadow: 0 0 0 3px var(--err-dim); animation: none; }}
  @keyframes pulse {{
    0%,100% {{ box-shadow: 0 0 0 3px var(--accent-dim); }}
    50%      {{ box-shadow: 0 0 0 6px var(--accent-dim); }}
  }}
  .card-header h1 {{
    font-size: 15px;
    font-weight: 500;
    letter-spacing: .01em;
    color: var(--text);
  }}
  .card-header .sub {{
    font-size: 12px;
    color: var(--muted);
    margin-top: 1px;
  }}

  .card-body {{ padding: 24px; }}

  .hero {{
    font-size: 22px;
    font-weight: 400;
    line-height: 1.35;
    margin-bottom: 20px;
    color: var(--text);
  }}
  .hero strong {{ color: var(--accent); font-weight: 500; }}

  .ip-row {{
    display: flex;
    align-items: center;
    gap: 10px;
    background: var(--bg);
    border: 1px solid var(--border-hi);
    border-radius: 8px;
    padding: 10px 14px;
    margin-bottom: 20px;
  }}
  .ip-label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--muted);
    flex-shrink: 0;
  }}
  .ip-value {{
    font-family: var(--mono);
    font-size: 15px;
    font-weight: 500;
    color: var(--text);
    letter-spacing: .02em;
  }}

  .status-list {{
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 20px;
  }}
  .status-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--bg);
  }}
  .status-row .label {{
    font-size: 13px;
    color: var(--muted);
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .status-row .label svg {{ opacity: .5; }}
  .badge {{
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 500;
    padding: 3px 9px;
    border-radius: 4px;
    letter-spacing: .04em;
    text-transform: uppercase;
  }}
  .badge.ok   {{ background: var(--accent-dim); color: var(--accent); }}
  .badge.skip {{ background: var(--border);     color: var(--muted); }}
  .badge.err  {{ background: var(--err-dim);    color: var(--err); }}

  .expiry {{
    font-size: 12px;
    color: var(--muted);
    text-align: center;
    margin-bottom: 20px;
    line-height: 1.5;
  }}
  .expiry span {{ color: var(--text); font-family: var(--mono); font-size: 12px; }}

  .details-toggle {{
    width: 100%;
    background: none;
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--muted);
    font-family: var(--sans);
    font-size: 12px;
    font-weight: 400;
    padding: 9px 14px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: border-color .15s, color .15s;
  }}
  .details-toggle:hover {{ border-color: var(--border-hi); color: var(--text); }}
  .chevron {{
    display: inline-block;
    transition: transform .2s;
    font-size: 10px;
    opacity: .6;
  }}
  .details-toggle[aria-expanded="true"] .chevron {{ transform: rotate(180deg); }}

  .details-body {{
    display: none;
    margin-top: 8px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.7;
    color: var(--muted);
  }}
  .details-body.open {{ display: block; animation: fadein .15s ease; }}
  @keyframes fadein {{ from {{ opacity:0 }} to {{ opacity:1 }} }}
  .details-body .key {{ color: var(--muted); }}
  .details-body .val {{ color: var(--text); }}
  .details-body .ok  {{ color: var(--accent); }}
  .details-body .bad {{ color: var(--err); }}
  .details-body .row {{ display: flex; gap: 8px; margin-bottom: 2px; }}

  .card-footer {{
    padding: 12px 24px;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--muted);
    text-align: center;
    letter-spacing: .02em;
  }}
</style>
</head>
<body>
<div class="card">
  <div class="card-header">
    <div class="{dot_class}"></div>
    <div>
      <h1>Network Check-in</h1>
      <div class="sub">thecolefam.com</div>
    </div>
  </div>

  <div class="card-body">
    <p class="hero">{hero}</p>

    <div class="ip-row">
      <span class="ip-label">Your IP</span>
      <span class="ip-value">{ip}</span>
    </div>

    <div class="status-list">
      <div class="status-row">
        <span class="label">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Pangolin access rule
        </span>
        {pangolin_badge}
      </div>
      <div class="status-row">
        <span class="label">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg>
          CrowdSec allowlist
        </span>
        {crowdsec_badge}
      </div>
    </div>

    <p class="expiry">
      Access expires <span>{expires_str}</span><br>
      (after {retention_minutes} minutes of inactivity)
    </p>

    <button class="details-toggle" aria-expanded="false" onclick="toggleDetails('details', this)">
      {details_label} <span class="chevron">&#9660;</span>
    </button>
    <div class="details-body" id="details">
      <div class="row"><span class="key">ip&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span class="val">{ip}</span></div>
      <div class="row"><span class="key">pangolin&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span class="{pangolin_detail_class}">{pangolin_detail}</span></div>
      <div class="row"><span class="key">crowdsec&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span class="{crowdsec_detail_class}">{crowdsec_detail_display}</span></div>
      <div class="row"><span class="key">retention&nbsp;&nbsp;&nbsp;&nbsp;</span><span class="val">{retention_minutes} min</span></div>
      <div class="row"><span class="key">expires_at&nbsp;&nbsp;&nbsp;</span><span class="val">{expires_iso}</span></div>
      <div class="row"><span class="key">last_seen&nbsp;&nbsp;&nbsp;&nbsp;</span><span class="val">{last_seen}</span></div>
    </div>
  </div>

  <div class="card-footer">Requests are logged &nbsp;&middot;&nbsp; Access resets on each visit</div>
</div>

<script>
  function toggleDetails(id, btn) {{
    const body = document.getElementById(id);
    const open = body.classList.toggle('open');
    btn.setAttribute('aria-expanded', open);
  }}
</script>
</body>
</html>"""


def create_image_request_handler(ctx: dict):
    """
    Factory that returns an ImageRequestHandler class bound to the provided context.
    Expected ctx keys:
      - expected_header_key: str
      - expected_header_value: str
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
                        print(f"[warn] Rejected non-global IP from header: {raw.strip()!r}")
                        return None
                    return str(ip_obj)
                except ValueError:
                    print(f"[warn] Rejected unparseable IP from header: {raw.strip()!r}")
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

        def do_GET(self):
            ip = self._get_real_ip()
            parsed_path = urlparse(self.path)
            path = (parsed_path.path or "/")
            remote_user = self.headers.get("Remote-User", "")

            print(f"New request from {ip}  user: {remote_user}  path: {path}")

            # Enforce Pangolin custom header (mandatory)
            actual = self.headers.get(ctx["expected_header_key"]) if ctx.get("expected_header_key") else None
            if actual is None or actual != ctx.get("expected_header_value"):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden: missing or invalid Pangolin custom header")
                print(f"[error] Missing or invalid Pangolin custom header: {actual}")
                return

            lower_path = path.lower()

            # /update?ip=1.2.3.4 endpoint (guarded by UPDATE_ENDPOINT_ENABLED)
            if lower_path == "/update":
                if not ctx.get("update_enabled"):
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not found")
                    print(f"[error] Update endpoint disabled: {self.path}")
                    return

                qs = parse_qs(parsed_path.query or "")
                raw_ip = (qs.get("ip", [""])[0] or "").strip()
                if not raw_ip:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Bad Request: missing 'ip' query parameter")
                    print(f"[error] Missing 'ip' query parameter: {self.path}")
                    return
                try:
                    normalized_ip = str(ipaddress.ip_address(raw_ip))
                except Exception:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Bad Request: invalid IP address")
                    print(f"[error] Invalid IP address: {raw_ip}")
                    return

                if not ipaddress.ip_address(normalized_ip).is_global:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Bad Request: non-routable IP address")
                    print(f"[error] Rejected non-global IP in /update: {normalized_ip!r}")
                    return

                with ctx["state_lock"]:
                    rec = ctx["state"].setdefault(normalized_ip, {"last_seen": ctx["now_utc_iso"](), "resources": {}})
                    rec["last_seen"] = ctx["now_utc_iso"]()
                ctx["save_state"]()

                try:
                    ctx["add_ip_to_targets"](normalized_ip)
                except Exception as e:
                    print(f"[error] add_ip_to_targets failed for {normalized_ip}: {e}")

                payload = (
                    "{"
                    f"\"ok\":true,\"ip\":\"{normalized_ip}\",\"retention_minutes\":{ctx.get('retention_minutes', 0)}"
                    "}"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
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
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found")
                print(f"[error] Invalid path (not .png/.gif): {self.path}")
                return

            # Update state
            now_iso = ctx["now_utc_iso"]()
            with ctx["state_lock"]:
                rec = ctx["state"].setdefault(ip, {"last_seen": now_iso, "resources": {}})
                rec["last_seen"] = now_iso
            ctx["save_state"]()

            # Run checkin against all targets
            results = {}
            try:
                results = ctx["add_ip_to_targets"](ip)
            except Exception as e:
                print(f"[error] add_ip_to_targets failed for {ip}: {e}")
                results = {
                    "pangolin": {"ok": False, "detail": str(e), "enabled": True},
                    "crowdsec": {"ok": False, "detail": "not reached", "enabled": ctx.get("crowdsec_enabled", False)},
                }

            # Browser gets the HTML page; everything else gets the transparent image
            if self._wants_html():
                html = _build_checkin_html(
                    ip=ip,
                    results=results,
                    retention_minutes=ctx.get("retention_minutes", 0),
                    last_seen=now_iso,
                    crowdsec_enabled=ctx.get("crowdsec_enabled", False),
                )
                body = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.end_headers()
                self.wfile.write(body)
            else:
                body = ctx["banner_gif"] if is_gif else ctx["banner_png"]
                ctype = "image/gif" if is_gif else "image/png"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.end_headers()
                self.wfile.write(body)

    return ImageRequestHandler
