from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import ipaddress


def create_image_request_handler(ctx: dict):
    """
    Factory that returns an ImageRequestHandler class bound to the provided context.
    Expected ctx keys:
      - expected_header_key: str
      - expected_header_value: str
      - state: dict
      - state_lock: threading.Lock
      - now_utc_iso: callable () -> str
      - save_state: callable () -> None
      - add_ip_to_targets: callable (ip: str) -> None
      - banner_png: bytes
      - banner_gif: bytes
      - redact_headers_for_log: callable (headers: dict[str, str]) -> dict[str, str]
    """

    class ImageRequestHandler(BaseHTTPRequestHandler):
        server_version = "BannerServer/1.0"

        def log_message(self, fmt, *args):
            # Minimal console logging
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

        def do_GET(self):
            ip = self._get_real_ip()
            parsed_path = urlparse(self.path)
            path = (parsed_path.path or "/")

            remote_user = self.headers.get("Remote-User", "")

            # Log request with sensitive headers redacted
            print(
                f"New request from {ip}  user: {remote_user}  path: {path} "
            )  # Headers: {json.dumps(redact_headers_for_log({k: v for k, v in self.headers.items()}))}

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
                    # Pretend it doesn't exist when disabled
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
                    # Normalize and validate (supports IPv4 and IPv6)
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

                # Update state and ensure rules for the provided IP using same retention behavior
                with ctx["state_lock"]:
                    rec = ctx["state"].setdefault(normalized_ip, {"last_seen": ctx["now_utc_iso"](), "resources": {}})
                    rec["last_seen"] = ctx["now_utc_iso"]()
                ctx["save_state"]()

                # Perform target updates synchronously (simple, small scale)
                try:
                    ctx["add_ip_to_targets"](normalized_ip)
                except Exception as e:
                    print(f"[error] add_ip_to_targets failed for {normalized_ip}: {e}")

                # Respond JSON summary
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

            # Explicitly forbid root path even if header is correct
            if path == "/":
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden")
                print(f"[error] Root path forbidden: {self.path}")
                return

            # Only serve PNG or GIF transparent images; other paths -> 404
            is_png = lower_path.endswith(".png")
            is_gif = lower_path.endswith(".gif")
            if not (is_png or is_gif):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found")
                print(f"[error] Invalid path (not .png/.gif): {self.path}")
                return

            # Update state and ensure rules
            with ctx["state_lock"]:
                rec = ctx["state"].setdefault(ip, {"last_seen": ctx["now_utc_iso"](), "resources": {}})
                rec["last_seen"] = ctx["now_utc_iso"]()
            ctx["save_state"]()

            # Perform target updates synchronously (simple, small scale)
            try:
                ctx["add_ip_to_targets"](ip)
            except Exception as e:
                print(f"[error] add_ip_to_targets failed for {ip}: {e}")

            # Serve transparent image according to extension
            body = ctx["banner_gif"] if is_gif else ctx["banner_png"]
            ctype = "image/gif" if is_gif else "image/png"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            # Prevent client/proxy caching to ensure periodic heartbeats reach the server
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(body)

    return ImageRequestHandler
