"""Lantern OSINT Workbench — desktop launcher.

Serves the bundled web app from a fixed loopback port (so the page origin — and therefore its saved
cases — stays the same between launches) and shows it in a native window using Microsoft Edge WebView2.

* Case data is stored in %LOCALAPPDATA%\\Lantern\\WebView (WebView2 profile), not in any browser.
* Pivot links open in your normal default browser.
* Nothing listens beyond 127.0.0.1, and requests with an unexpected Host header are refused.
"""
from __future__ import annotations

import ctypes
import http.server
import os
import sys
import threading
import urllib.request
from pathlib import Path

APP_NAME = "Lantern — OSINT Workbench"
PORT = 47863  # fixed: the origin must not change between runs or saved cases would "disappear"
HOST = "127.0.0.1"
ALLOWED_HOSTS = {f"{HOST}:{PORT}", f"localhost:{PORT}"}
PING_PATH = "/__lantern_ping"


def web_root() -> Path:
    """Folder holding index.html: bundled next to the exe when frozen, the repo root when run from source."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "web"  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    d = base / "Lantern" / "WebView"
    d.mkdir(parents=True, exist_ok=True)
    return d


def message_box(text: str, title: str = "Lantern", error: bool = False) -> None:
    try:
        ctypes.windll.user32.MessageBoxW(None, text, title, 0x10 if error else 0x40)
    except Exception:  # not on Windows / no GUI
        print(f"{title}: {text}", file=sys.stderr)


class Handler(http.server.SimpleHTTPRequestHandler):
    # Explicit types: the Windows registry can map .js to text/plain, which nosniff would then block.
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".html": "text/html; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".json": "application/json",
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".ico": "image/x-icon",
        ".md": "text/markdown; charset=utf-8",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(web_root()), **kwargs)

    def log_message(self, *args) -> None:  # keep the windowed app silent
        pass

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        super().end_headers()

    def _allowed(self) -> bool:
        # Blocks DNS-rebinding style requests from web pages that resolve their own name to 127.0.0.1.
        if self.headers.get("Host", "") not in ALLOWED_HOSTS:
            self.send_error(403, "Forbidden")
            return False
        return True

    def do_GET(self) -> None:
        if not self._allowed():
            return
        if self.path == PING_PATH:
            body = b"lantern"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_HEAD(self) -> None:
        if self._allowed():
            super().do_HEAD()

    def list_directory(self, path):  # no directory listings
        self.send_error(404, "Not found")
        return None


def already_running() -> bool:
    try:
        with urllib.request.urlopen(f"http://{HOST}:{PORT}{PING_PATH}", timeout=1.5) as r:
            return r.read() == b"lantern"
    except Exception:
        return False


def start_server() -> http.server.ThreadingHTTPServer:
    server = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="lantern-http", daemon=True).start()
    return server


def main() -> int:
    if not (web_root() / "index.html").is_file():
        message_box(f"App files are missing from:\n{web_root()}", error=True)
        return 1
    try:
        server = start_server()
    except OSError:
        if already_running():
            message_box("Lantern is already open.")
        else:
            message_box(f"Port {PORT} on 127.0.0.1 is in use by another program, so Lantern can't start.", error=True)
        return 1

    try:
        import webview  # pywebview
    except ImportError:
        message_box("pywebview is not installed. Run:  pip install pywebview", error=True)
        return 1

    webview.settings["ALLOW_DOWNLOADS"] = True                # CSV / JSON / report / PNG exports
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True  # pivots open in the default browser
    webview.create_window(
        APP_NAME,
        f"http://{HOST}:{PORT}/index.html#/dashboard",
        width=1400,
        height=900,
        min_size=(880, 600),
        background_color="#0d0d0d",
        text_select=True,
    )
    try:
        webview.start(gui="edgechromium", private_mode=False, storage_path=str(data_dir()), debug="--debug" in sys.argv)
    except Exception as exc:  # WebView2 runtime missing or broken
        message_box(
            "Lantern needs the Microsoft Edge WebView2 Runtime (built into Windows 11).\n"
            "Install it from https://developer.microsoft.com/microsoft-edge/webview2/\n\n"
            f"Details: {exc}",
            error=True,
        )
        return 1
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
