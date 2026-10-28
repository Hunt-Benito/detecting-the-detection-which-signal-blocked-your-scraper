#!/usr/bin/env python3
"""Step 4 of the walkthrough: a local detection lab.

A stdlib-only HTTP server that behaves like a simplified bot-detection
vendor, with three switchable enforcement layers. It gives you a
deterministic target to validate the attribution logic against - real
sites change their minds between requests (as you will see in the
article), the lab always blocks the same way.

Modes:
  off     serves a plain page (control)
  header  blocks at the HTTP layer: 403 if User-Agent or sec-ch-ua
          contains HeadlessChrome - the exact header-level gate that
          arXiv:2606.14525 found behind 75% of headless-only blocks
  js      lets the request through with HTTP 200, then a client-side
          script checks navigator.webdriver and the UA Client Hints brands
          and REPLACES the page content on detection - status stays 200,
          which is exactly the "content degradation inside HTTP 200" blind
          spot the Bamberg study lists among its limitations

The js-mode script also reads the classic automation-framework names
(window._selenium, callPhantom, ...) exactly the way real detection
scripts do - run 03_honeypot.py against the lab to watch it happen.

Usage (terminal 1):
    python 04_detection_lab.py --mode header [--port 8980]
Usage (terminal 2):
    python 02_probe.py http://127.0.0.1:8980/ --display :0
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<!DOCTYPE html>
<html><head><title>detection lab</title>
<script>
(function () {
  var reasons = [];
  if (navigator.webdriver === true) reasons.push('navigator.webdriver');
  try {
    var brands = navigator.userAgentData.brands || [];
    for (var i = 0; i < brands.length; i++)
      if (brands[i].brand === 'HeadlessChrome')
        reasons.push('userAgentData.brands:HeadlessChrome');
  } catch (e) { /* Firefox: no userAgentData at all */ }
  if (/HeadlessChrome/.test(navigator.userAgent))
    reasons.push('UA-token:HeadlessChrome');

  var probes = ['_selenium', 'callSelenium', '_Selenium_IDE_Recorder',
                'callPhantom', '_phantom', '__nightmare',
                'domAutomationController'];
  for (var j = 0; j < probes.length; j++) { void window[probes[j]]; }

  if (reasons.length) {
    document.title = 'BLOCKED';
    document.documentElement.innerHTML =
      '<body><h1>blocked by detection lab (js)</h1><p>' +
      reasons.join(', ') + '</p></body>';
  }
})();
</script></head>
<body><h1>lab page</h1>
<p>If you can read this, the client-side check did not flag you.</p>
</body></html>
"""

BLOCK_PAGE = """<!DOCTYPE html>
<html><head><title>blocked</title></head>
<body><h1>403 - blocked by detection lab ({where})</h1>
<p>{reasons}</p></body></html>
"""

PLAIN_PAGE = """<!DOCTYPE html>
<html><head><title>detection lab</title></head>
<body><h1>lab page (mode: off)</h1>
<p>No detection of any kind runs on this page. Every configuration
should receive it untouched - your control condition.</p>
</body></html>
"""

OK_PAGE = """<!DOCTYPE html>
<html><head><title>ok</title></head>
<body><h1>200 - lab page (mode: header, no header tell found)</h1>
</body></html>
"""


class LabHandler(BaseHTTPRequestHandler):
    mode = "off"

    def _send(self, status, body):
        body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/blocked"):
            reasons = self.path.split("reasons=")[-1][:200]
            self._send(403, BLOCK_PAGE.format(where="js", reasons=reasons))
            return
        if self.mode == "header":
            ua = self.headers.get("User-Agent", "")
            ch = self.headers.get("sec-ch-ua", "")
            if "HeadlessChrome" in ua:
                self._send(403, BLOCK_PAGE.format(
                    where="header", reasons="User-Agent contains HeadlessChrome"))
                return
            if "HeadlessChrome" in ch:
                self._send(403, BLOCK_PAGE.format(
                    where="header", reasons="sec-ch-ua contains HeadlessChrome"))
                return
            self._send(200, OK_PAGE)
            return
        if self.mode == "off":
            self._send(200, PLAIN_PAGE)
            return
        self._send(200, PAGE)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["off", "header", "js"], default="off")
    parser.add_argument("--port", type=int, default=8980)
    args = parser.parse_args()

    LabHandler.mode = args.mode
    server = ThreadingHTTPServer(("127.0.0.1", args.port), LabHandler)
    print(f"[*] detection lab listening on http://127.0.0.1:{args.port}/ "
          f"(mode: {args.mode})")
    print("[*] point 02_probe.py or 03_honeypot.py at it, Ctrl+C to stop")
    server.serve_forever()


if __name__ == "__main__":
    main()
