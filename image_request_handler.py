from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta, timezone
import ipaddress


def _build_checkin_html(
    ip: str,
    results: dict,
    retention_minutes: int,
    last_seen: str,
    crowdsec_enabled: bool,
    access_check_enabled: bool = False,
    access_check_url: str = "",
    site_name: str = "",
) -> str:
    """Build the HTML checkin response page."""

    try:
        seen_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        expires_dt = seen_dt + timedelta(minutes=retention_minutes)
        expires_str = expires_dt.strftime("%Y-%m-%d %H:%M UTC")
        expires_iso = expires_dt.isoformat()
    except Exception:
        expires_str = "unknown"
        expires_iso = "unknown"

    pangolin_ok = results.get("pangolin", {}).get("ok", False)
    pangolin_detail = results.get("pangolin", {}).get("detail", "unknown")
    crowdsec_ok = results.get("crowdsec", {}).get("ok", False)
    crowdsec_detail = results.get("crowdsec", {}).get("detail", "disabled")
    overall_ok = pangolin_ok

    dot_class = "status-dot" if overall_ok else "status-dot err"
    if overall_ok:
        hero = "You&#39;re all set!<br><strong>Jellyfin should work on your TV.</strong>"
    else:
        hero = "Something went wrong.<br><strong>Jellyfin may not work right now &mdash; try again in a moment.</strong>"

    pangolin_badge = '<span class="badge ok">Added</span>' if pangolin_ok else '<span class="badge err">Failed</span>'

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

    # Access check link — only rendered when both enabled and a URL is configured
    show_access_check = access_check_enabled and bool(access_check_url)
    if show_access_check:
        # Escape the URL for safe inline HTML attribute embedding
        safe_url = (
            access_check_url
            .replace("&", "&amp;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        access_check_row = (
            "      <a class=\"access-link\" href=\"" + safe_url + "\" target=\"_blank\" rel=\"noopener noreferrer\">\n"
            "        <span class=\"access-link-left\">\n"
            "          <svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" style=\"flex-shrink:0;\">"
            "<path d=\"M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6\"/>"
            "<polyline points=\"15 3 21 3 21 9\"/><line x1=\"10\" y1=\"14\" x2=\"21\" y2=\"3\"/>"
            "</svg>\n"
            "          <span class=\"access-link-text\">\n"
            "            <span class=\"access-link-label\">Confirm access</span>\n"
            f"            <span class=\"access-link-url\">{safe_url}</span>\n"
            "          </span>\n"
            "        </span>\n"
            "        <svg class=\"access-link-arrow\" width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\">"
            "<line x1=\"5\" y1=\"12\" x2=\"19\" y2=\"12\"/>"
            "<polyline points=\"12 5 19 12 12 19\"/>"
            "</svg>\n"
            "      </a>"
        )
        access_check_detail_rows = (
            "      <div class=\"row\"><span class=\"key\">ac_url&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>"
            "<span class=\"val\" style=\"word-break:break-all;\">" + safe_url + "</span></div>\n"
        )
    else:
        access_check_row = ""
        access_check_detail_rows = ""

    # Bookmark row — always shown on success, uses current page URL via JS
    bookmark_row = (
        "      <button class=\"bookmark-btn\" onclick=\"bookmarkPage()\">\n"
        "        <span class=\"access-link-left\">\n"
        "          <svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" style=\"flex-shrink:0;\">"
        "<path d=\"M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z\"/>"
        "</svg>\n"
        "          <span class=\"access-link-text\">\n"
        "            <span class=\"access-link-label\">Bookmark this page</span>\n"
        "            <span class=\"access-link-url\">Save for one-tap access next time</span>\n"
        "          </span>\n"
        "        </span>\n"
        "        <svg class=\"access-link-arrow\" width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\">"
        "<line x1=\"5\" y1=\"12\" x2=\"19\" y2=\"12\"/>"
        "<polyline points=\"12 5 19 12 12 19\"/>"
        "</svg>\n"
        "      </button>"
    ) if overall_ok else ""

    site_name_sub = f'      <div class="sub">{site_name}</div>\n' if site_name else ""
    html = (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "<title>Network Check-in</title>\n"
        "<style>\n"
        "  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500&display=swap');\n"
        "  :root {\n"
        "    --bg:        #0d0f12;\n"
        "    --surface:   #151820;\n"
        "    --border:    #232733;\n"
        "    --border-hi: #2e3344;\n"
        "    --text:      #e2e6f0;\n"
        "    --muted:     #6b7390;\n"
        "    --accent:    #4ade80;\n"
        "    --accent-dim:#1a3d28;\n"
        "    --warn:      #fbbf24;\n"
        "    --warn-dim:  #3d2e0a;\n"
        "    --err:       #f87171;\n"
        "    --err-dim:   #3d1515;\n"
        "    --mono:      'IBM Plex Mono', monospace;\n"
        "    --sans:      'IBM Plex Sans', sans-serif;\n"
        "  }\n"
        "  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "  body {\n"
        "    background: var(--bg);\n"
        "    color: var(--text);\n"
        "    font-family: var(--sans);\n"
        "    font-weight: 300;\n"
        "    min-height: 100vh;\n"
        "    display: flex;\n"
        "    flex-direction: column;\n"
        "    align-items: center;\n"
        "    justify-content: flex-start;\n"
        "    padding: 40px 16px 48px;\n"
        "    background-image:\n"
        "      linear-gradient(var(--border) 1px, transparent 1px),\n"
        "      linear-gradient(90deg, var(--border) 1px, transparent 1px);\n"
        "    background-size: 32px 32px;\n"
        "    background-position: center center;\n"
        "  }\n"
        "  .card {\n"
        "    width: 100%;\n"
        "    max-width: 440px;\n"
        "    background: var(--surface);\n"
        "    border: 1px solid var(--border-hi);\n"
        "    border-radius: 12px;\n"
        "    overflow: hidden;\n"
        "    box-shadow: 0 8px 48px rgba(0,0,0,.5);\n"
        "    animation: rise .45s cubic-bezier(.22,1,.36,1) both;\n"
        "  }\n"
        "  @keyframes rise {\n"
        "    from { opacity:0; transform: translateY(18px); }\n"
        "    to   { opacity:1; transform: translateY(0); }\n"
        "  }\n"
        "  .card-header {\n"
        "    padding: 20px 24px 18px;\n"
        "    border-bottom: 1px solid var(--border);\n"
        "    display: flex;\n"
        "    align-items: center;\n"
        "    gap: 12px;\n"
        "  }\n"
        "  .status-dot {\n"
        "    width: 10px; height: 10px;\n"
        "    border-radius: 50%;\n"
        "    background: var(--accent);\n"
        "    box-shadow: 0 0 0 3px var(--accent-dim);\n"
        "    flex-shrink: 0;\n"
        "    animation: pulse 2.4s ease-in-out infinite;\n"
        "  }\n"
        "  .status-dot.err { background: var(--err); box-shadow: 0 0 0 3px var(--err-dim); animation: none; }\n"
        "  @keyframes pulse {\n"
        "    0%,100% { box-shadow: 0 0 0 3px var(--accent-dim); }\n"
        "    50%      { box-shadow: 0 0 0 6px var(--accent-dim); }\n"
        "  }\n"
        "  .card-header h1 { font-size: 15px; font-weight: 500; letter-spacing: .01em; color: var(--text); }\n"
        "  .card-header .sub { font-size: 12px; color: var(--muted); margin-top: 1px; }\n"
        "  .card-body { padding: 24px; }\n"
        "  .hero { font-size: 22px; font-weight: 400; line-height: 1.35; margin-bottom: 20px; color: var(--text); }\n"
        "  .hero strong { color: var(--accent); font-weight: 500; }\n"
        "  .ip-row {\n"
        "    display: flex; align-items: center; gap: 10px;\n"
        "    background: var(--bg); border: 1px solid var(--border-hi);\n"
        "    border-radius: 8px; padding: 10px 14px; margin-bottom: 20px;\n"
        "  }\n"
        "  .ip-label { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); flex-shrink: 0; }\n"
        "  .ip-value { font-family: var(--mono); font-size: 15px; font-weight: 500; color: var(--text); letter-spacing: .02em; }\n"
        "  .status-list { display: flex; flex-direction: column; gap: 8px; margin-bottom: 20px; }\n"
        "  .status-row {\n"
        "    display: flex; align-items: center; justify-content: space-between;\n"
        "    padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border); background: var(--bg);\n"
        "  }\n"
        "  .status-row .label { font-size: 13px; color: var(--muted); display: flex; align-items: center; gap: 8px; }\n"
        "  .status-row .label svg { opacity: .5; flex-shrink: 0; }\n"
        "  .badge { font-family: var(--mono); font-size: 11px; font-weight: 500; padding: 3px 9px; border-radius: 4px; letter-spacing: .04em; text-transform: uppercase; }\n"
        "  .badge.ok      { background: var(--accent-dim); color: var(--accent); }\n"
        "  .badge.skip    { background: var(--border);     color: var(--muted); }\n"
        "  .badge.err     { background: var(--err-dim);    color: var(--err); }\n"
        "  .badge.warn    { background: var(--warn-dim);   color: var(--warn); }\n"
        "  .access-link {\n"
        "    display: flex; align-items: center; justify-content: space-between;\n"
        "    padding: 10px 14px; border-radius: 8px; border: 1px solid var(--accent-dim);\n"
        "    background: var(--bg); text-decoration: none; cursor: pointer;\n"
        "    transition: border-color .15s, background .15s;\n"
        "  }\n"
        "  .access-link:hover { border-color: var(--accent); background: #0d1f16; }\n"
        "  .access-link-left { display: flex; align-items: center; gap: 8px; min-width: 0; }\n"
        "  .access-link-left svg { opacity: .6; color: var(--accent); stroke: var(--accent); }\n"
        "  .access-link-text { display: flex; flex-direction: column; gap: 1px; min-width: 0; }\n"
        "  .access-link-label { font-size: 13px; font-weight: 500; color: var(--accent); }\n"
        "  .access-link-url { font-family: var(--mono); font-size: 10px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n"
        "  .access-link-arrow { color: var(--accent); stroke: var(--accent); opacity: .7; flex-shrink: 0; transition: transform .15s; }\n"
        "  .access-link:hover .access-link-arrow { transform: translateX(3px); opacity: 1; }\n  .bookmark-btn {\n    width: 100%; background: none; border: 1px solid var(--accent-dim); border-radius: 8px;\n    padding: 10px 14px; cursor: pointer; display: flex; align-items: center;\n    justify-content: space-between; transition: border-color .15s, background .15s;\n  }\n  .bookmark-btn:hover { border-color: var(--accent); background: #0d1f16; }\n  .bookmark-btn .access-link-left { display: flex; align-items: center; gap: 8px; min-width: 0; }\n  .bookmark-btn .access-link-left svg { opacity: .6; color: var(--accent); stroke: var(--accent); }\n  .bookmark-btn .access-link-label { font-size: 13px; font-weight: 500; color: var(--accent); }\n  .bookmark-btn .access-link-url { font-family: var(--mono); font-size: 10px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n  .bookmark-btn .access-link-arrow { color: var(--accent); stroke: var(--accent); opacity: .7; flex-shrink: 0; transition: transform .15s; }\n  .bookmark-btn:hover .access-link-arrow { transform: translateX(3px); opacity: 1; }\n"
        "  .expiry { font-size: 12px; color: var(--muted); text-align: center; margin-bottom: 20px; line-height: 1.5; }\n"
        "  .expiry span { color: var(--text); font-family: var(--mono); font-size: 12px; }\n"
        "  .details-toggle {\n"
        "    width: 100%; background: none; border: 1px solid var(--border); border-radius: 8px;\n"
        "    color: var(--muted); font-family: var(--sans); font-size: 12px; font-weight: 400;\n"
        "    padding: 9px 14px; cursor: pointer; display: flex; align-items: center;\n"
        "    justify-content: space-between; transition: border-color .15s, color .15s;\n"
        "  }\n"
        "  .details-toggle:hover { border-color: var(--border-hi); color: var(--text); }\n"
        "  .chevron { display: inline-block; transition: transform .2s; font-size: 10px; opacity: .6; }\n"
        "  .details-toggle[aria-expanded=\"true\"] .chevron { transform: rotate(180deg); }\n"
        "  .details-body {\n"
        "    display: none; margin-top: 8px; background: var(--bg); border: 1px solid var(--border);\n"
        "    border-radius: 8px; padding: 14px; font-family: var(--mono); font-size: 12px; line-height: 1.7; color: var(--muted);\n"
        "  }\n"
        "  .details-body.open { display: block; animation: fadein .15s ease; }\n"
        "  @keyframes fadein { from { opacity:0 } to { opacity:1 } }\n"
        "  .details-body .key { color: var(--muted); }\n"
        "  .details-body .val { color: var(--text); }\n"
        "  .details-body .ok  { color: var(--accent); }\n"
        "  .details-body .bad { color: var(--err); }\n"
        "  .details-body .row { display: flex; gap: 8px; margin-bottom: 2px; }\n"
        "  .card-footer { padding: 12px 24px; border-top: 1px solid var(--border); font-size: 11px; color: var(--muted); text-align: center; letter-spacing: .02em; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<div class=\"card\">\n"
        "  <div class=\"card-header\">\n"
        f"    <div class=\"{dot_class}\"></div>\n"
        "    <div>\n"
        "      <h1>Network Check-in</h1>\n"
        + site_name_sub
        + "    </div>\n"
        "  </div>\n"
        "  <div class=\"card-body\">\n"
        f"    <p class=\"hero\">{hero}</p>\n"
        "    <div class=\"ip-row\">\n"
        "      <span class=\"ip-label\">Your IP</span>\n"
        f"      <span class=\"ip-value\">{ip}</span>\n"
        "    </div>\n"
        "    <div class=\"status-list\">\n"
        "      <div class=\"status-row\">\n"
        "        <span class=\"label\">\n"
        "          <svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/></svg>\n"
        "          Pangolin access rule\n"
        "        </span>\n"
        f"        {pangolin_badge}\n"
        "      </div>\n"
        "      <div class=\"status-row\">\n"
        "        <span class=\"label\">\n"
        "          <svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M12 8v4l3 3\"/></svg>\n"
        "          CrowdSec allowlist\n"
        "        </span>\n"
        f"        {crowdsec_badge}\n"
        "      </div>\n"
        f"{access_check_row}\n"
        f"{bookmark_row}\n"
        "    </div>\n"
        "    <p class=\"expiry\">\n"
        f"      Access expires <span>{expires_str}</span><br>\n"
        f"      (after {retention_minutes} minutes of inactivity)\n"
        "    </p>\n"
        f"    <button class=\"details-toggle\" aria-expanded=\"false\" onclick=\"toggleDetails('details', this)\">\n"
        f"      {details_label} <span class=\"chevron\">&#9660;</span>\n"
        "    </button>\n"
        "    <div class=\"details-body\" id=\"details\">\n"
        f"      <div class=\"row\"><span class=\"key\">ip&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span class=\"val\">{ip}</span></div>\n"
        f"      <div class=\"row\"><span class=\"key\">pangolin&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span class=\"{pangolin_detail_class}\">{pangolin_detail}</span></div>\n"
        f"      <div class=\"row\"><span class=\"key\">crowdsec&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span class=\"{crowdsec_detail_class}\">{crowdsec_detail_display}</span></div>\n"
        f"      <div class=\"row\"><span class=\"key\">retention&nbsp;&nbsp;&nbsp;&nbsp;</span><span class=\"val\">{retention_minutes} min</span></div>\n"
        f"      <div class=\"row\"><span class=\"key\">expires_at&nbsp;&nbsp;&nbsp;</span><span class=\"val\">{expires_iso}</span></div>\n"
        f"      <div class=\"row\"><span class=\"key\">last_seen&nbsp;&nbsp;&nbsp;&nbsp;</span><span class=\"val\">{last_seen}</span></div>\n"
        f"{access_check_detail_rows}"
        "    </div>\n"
        "  </div>\n"
        "  <div class=\"card-footer\">Requests are logged &nbsp;&middot;&nbsp; Access resets on each visit</div>\n"
        "</div>\n"
        "<script>\n"
        "  function toggleDetails(id, btn) {\n"
        "    const body = document.getElementById(id);\n"
        "    const open = body.classList.toggle('open');\n"
        "    btn.setAttribute('aria-expanded', open);\n"
        "  }\n"
        "  function bookmarkPage() {\n"
        "    const url = window.location.href;\n"
        "    if (navigator.share) {\n"
        "      navigator.share({ title: 'Network Check-in', url: url }).catch(() => {});\n"
        "    } else {\n"
        "      navigator.clipboard.writeText(url).then(function() {\n"
        "        alert('Link copied to clipboard — paste it into your bookmarks.');\n"
        "      }).catch(function() {\n"
        "        prompt('Copy this link and save it as a bookmark:', url);\n"
        "      });\n"
        "    }\n"
        "  }\n"
        "</script>\n"
        "</body>\n"
        "</html>"
    )
    return html


def _build_error_html(title: str, message: str, site_name: str = "") -> str:
    """Build a minimal HTML error page matching the checkin page style."""
    site_name_sub = f'      <div class="sub">{site_name}</div>\n' if site_name else ""
    site_name_footer = f'{site_name} &nbsp;&middot;&nbsp; ' if site_name else ""
    html = (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        f"<title>{title}</title>\n"
        "<style>\n"
        "  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500&display=swap');\n"
        "  :root {\n"
        "    --bg:        #0d0f12;\n"
        "    --surface:   #151820;\n"
        "    --border:    #232733;\n"
        "    --border-hi: #2e3344;\n"
        "    --text:      #e2e6f0;\n"
        "    --muted:     #6b7390;\n"
        "    --err:       #f87171;\n"
        "    --err-dim:   #3d1515;\n"
        "    --sans:      'IBM Plex Sans', sans-se