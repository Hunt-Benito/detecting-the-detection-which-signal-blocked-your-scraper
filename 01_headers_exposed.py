#!/usr/bin/env python3
"""Step 1 of the walkthrough: show exactly what each browser configuration
announces about itself in HTTP headers, using a local echo server.

No external traffic: the browser talks to 127.0.0.1 only. This is the
"confession table" - everything a site can read before a single line of
page JavaScript runs.

Usage:
    python 01_headers_exposed.py [--display :0]

Requires: playwright (pip install playwright) and its browsers
(playwright install chromium chromium-headless-shell firefox).
The headed configuration needs a display: run inside a desktop session,
under Xvfb, or pass --display.
"""

import argparse
import http.server
import json
import threading

from playwright.sync_api import sync_playwright

ECHO_PORT = 8977

INTERESTING = [
    "user-agent",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "accept-language",
]

CHROME_HEADERS_TELLS = ["HeadlessChrome", "headless"]


class EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_echo_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", ECHO_PORT), EchoHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def fetch_headers(page):
    resp = page.goto(f"http://127.0.0.1:{ECHO_PORT}/echo", timeout=20000)
    headers = resp.json()
    webdriver = page.evaluate("navigator.webdriver")
    return headers, webdriver


def report(name, headers, webdriver):
    print(f"\n--- {name}")
    for key in INTERESTING:
        value = headers.get(key)
        marker = ""
        if value and any(t in value for t in CHROME_HEADERS_TELLS):
            marker = "   <-- automation tell"
        print(f"    {key}: {value}{marker}")
    print(f"    navigator.webdriver: {webdriver}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--display", default=None,
                        help="X display for the headed run, e.g. :0")
    args = parser.parse_args()

    start_echo_server()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        report("chromium headless shell (Playwright default)",
               *fetch_headers(page))
        browser.close()

        browser = p.chromium.launch(headless=True, channel="chromium")
        page = browser.new_page()
        report("chromium full binary, headless (channel=chromium)",
               *fetch_headers(page))
        browser.close()

        import os
        display = args.display or os.environ.get("DISPLAY")
        if display:
            os.environ["DISPLAY"] = display
            browser = p.chromium.launch(headless=False, channel="chromium")
            page = browser.new_page()
            report("chromium full binary, HEADED (the human baseline)",
                   *fetch_headers(page))
            browser.close()
        else:
            print("\n--- chromium headed: skipped (no DISPLAY available)")

        browser = p.firefox.launch(headless=True)
        page = browser.new_page()
        report("firefox headless (no Client Hints support)", *fetch_headers(page))
        browser.close()

    print("\nRead the table top to bottom: everything that differs between")
    print("the headless shell and the headed run is a header-level signal a")
    print("site can block on without ever running page JavaScript.")


if __name__ == "__main__":
    main()
