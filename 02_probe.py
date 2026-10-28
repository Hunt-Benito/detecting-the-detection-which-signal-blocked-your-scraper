#!/usr/bin/env python3
"""Step 2 of the walkthrough: the differential blocking prober.

Runs one URL through six client configurations that differ in exactly one
signal layer at a time, records HTTP status + vendor signatures for each,
and prints an attribution verdict: which layer most plausibly blocked you.

Configurations:
  plain-http             raw httpx client, library default User-Agent
  plain-http-chrome      raw httpx client, full headed-Chrome header set
  shell-headless         Playwright default (chrome headless shell)
  shell-headless-spoofed same shell, UA + sec-ch-ua patched to headed values
  chromium-headed        full Chromium, headful (needs a display)
  firefox-headless       Firefox headless (sends no Client Hints at all)

A "soft block" is HTTP 403/429/503, the same classification the Bamberg
measurement study uses (arXiv:2606.14525).

Usage:
    python 02_probe.py URL [URL ...] [--proxy socks5://user:pass@host:port]
                       [--display :0] [--timeout 30] [--json out.json]
"""

import argparse
import json
import sys

import httpx

SOFT_BLOCKS = {403, 429, 503}

CHROME_HEADER_SET = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
    "sec-ch-ua": '"Not:A-Brand";v="8", "Chromium";v="156"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Linux"',
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

VENDOR_SIGNATURES = [
    ("Cloudflare", {
        "headers": {"cf-mitigated": "challenge"},
        "body": ["challenges.cloudflare.com", "cdn-cgi/challenge-platform",
                 "Just a moment", "Attention Required! | Cloudflare"],
    }),
    ("DataDome", {
        "headers": {"x-dd-b": None},
        "body": ["datadome", "captcha-delivery"],
    }),
    ("PerimeterX/HUMAN", {
        "headers": {},
        "body": ["px-captcha", "perimeterx", "px-cloud", "captcha-delivery"],
    }),
    ("Imperva/Incapsula", {
        "headers": {"x-iinfo": None},
        "body": ["incapsula", "_incap_"],
    }),
    ("Akamai", {
        "headers": {},
        "body": ["akamai", "reference #"],
    }),
    ("generic CAPTCHA", {
        "headers": {},
        "body": ["recaptcha/api", "hcaptcha.com"],
    }),
]


def classify_vendor(headers, body_text, cookies=""):
    haystack = (body_text or "").lower()
    for vendor, sig in VENDOR_SIGNATURES:
        for header, value in sig["headers"].items():
            if header.lower() in {k.lower() for k in headers}:
                if value is None or value.lower() in headers.get(header, "").lower():
                    return vendor
        for marker in sig["body"]:
            if marker.lower() in haystack:
                return vendor
    return None


def probe_http(url, proxy=None, chrome_headers=False, timeout=30):
    name = "plain-http-chrome" if chrome_headers else "plain-http"
    headers = dict(CHROME_HEADER_SET) if chrome_headers else {}
    transport_kwargs = {}
    client_kwargs = {"follow_redirects": True, "timeout": timeout}
    if proxy:
        client_kwargs["proxy"] = proxy
    try:
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(url, headers=headers)
            body = resp.text[:60000]
            vendor = classify_vendor(dict(resp.headers), body)
            ua_sent = headers.get("User-Agent", f"httpx/{httpx.__version__}")
            return {"config": name, "status": resp.status_code,
                    "blocked": resp.status_code in SOFT_BLOCKS,
                    "vendor": vendor, "ua": ua_sent,
                    "final_url": str(resp.url), "error": None}
    except Exception as exc:
        return {"config": name, "status": None, "blocked": False, "vendor": None,
                "ua": headers.get("User-Agent", "httpx"), "final_url": url,
                "error": f"{type(exc).__name__}: {exc}"[:120]}


def probe_browser(url, engine="chromium", mode="headless", spoof_headers=False,
                  headed=False, display=None, proxy=None, timeout=30):
    from playwright.sync_api import sync_playwright
    name = {("chromium", "headless"): "shell-headless",
            ("chromium", "spoofed"): "shell-headless-spoofed",
            ("chromium", "headed"): "chromium-headed",
            ("firefox", "headless"): "firefox-headless"}[(engine, mode)]

    launch_kwargs = {"headless": not headed}
    if proxy:
        launch_kwargs["proxy"] = {"server": proxy}
    result = {"config": name, "status": None, "blocked": False, "vendor": None,
              "ua": None, "final_url": url, "error": None, "webdriver": None}

    import os
    if headed:
        if display:
            os.environ["DISPLAY"] = display
        if not os.environ.get("DISPLAY"):
            result["error"] = "no DISPLAY for headed run (pass --display)"
            return result

    with sync_playwright() as p:
        browser_type = p.chromium if engine == "chromium" else p.firefox
        browser = browser_type.launch(**launch_kwargs)
        context = browser.new_context(locale="en-GB")
        page = context.new_page()

        if spoof_headers:
            version = browser.version.split(".")[0]
            headed_ua = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                         f"(KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36")
            cdp = context.new_cdp_session(page)
            cdp.send("Network.setUserAgentOverride", {
                "userAgent": headed_ua,
                "acceptLanguage": "en-GB,en-US;q=0.9,en;q=0.8",
                "userAgentMetadata": {
                    "brands": [{"brand": "Chromium", "version": version},
                               {"brand": "Not:A-Brand", "version": "8"}],
                    "fullVersionList": [
                        {"brand": "Chromium", "version": f"{version}.0.0.0"},
                        {"brand": "Not:A-Brand", "version": "8.0.0.0"}],
                    "fullVersion": f"{version}.0.0.0",
                    "platform": "Linux", "platformVersion": "",
                    "architecture": "x86", "model": "", "mobile": False,
                    "bitness": "64", "wow64": False,
                },
            })

        first_request = {}
        page.on("request", lambda req: first_request.setdefault(
            "headers", req.headers) if req.url.rstrip("/") == url.rstrip("/") else None)

        try:
            resp = page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
            page.wait_for_timeout(2500)
            headers = dict(resp.headers) if resp else {}
            try:
                body = resp.text()[:60000] if resp else ""
            except Exception:
                body = page.content()[:60000]
            page_body = page.content()[:60000]
            lab_block = "blocked by detection lab (js)" in page_body
            lab_reasons = ""
            if lab_block:
                import re as _re
                m = _re.search(r"<p>(.*?)</p>", page_body, _re.S)
                lab_reasons = (m.group(1).strip()[:80] if m else "")
            result.update({
                "status": resp.status if resp else None,
                "blocked": bool(resp and resp.status in SOFT_BLOCKS) or lab_block,
                "vendor": classify_vendor(headers, body) or classify_vendor({}, page_body),
                "final_url": page.url,
                "lab_block": lab_block,
                "lab_reasons": lab_reasons,
            })
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"[:120]
        finally:
            ua = (first_request.get("headers") or {}).get("user-agent")
            result["ua"] = ua or ("(no request captured)")
            try:
                result["webdriver"] = page.evaluate("navigator.webdriver")
            except Exception:
                pass
            browser.close()
    return result


def run_all_configs(url, args):
    results = []
    results.append(probe_http(url, args.proxy, chrome_headers=False,
                              timeout=args.timeout))
    results.append(probe_http(url, args.proxy, chrome_headers=True,
                              timeout=args.timeout))
    results.append(probe_browser(url, engine="chromium", mode="headless",
                                 proxy=args.proxy, timeout=args.timeout))
    results.append(probe_browser(url, engine="chromium", mode="spoofed",
                                 spoof_headers=True, proxy=args.proxy,
                                 timeout=args.timeout))
    results.append(probe_browser(url, engine="chromium", mode="headed",
                                 headed=True, display=args.display,
                                 proxy=args.proxy, timeout=args.timeout))
    results.append(probe_browser(url, engine="firefox", mode="headless",
                                 proxy=args.proxy, timeout=args.timeout))
    return results


def attribute(results):
    by = {r["config"]: r for r in results}
    def ok(cfg):
        r = by.get(cfg)
        return r is not None and r["blocked"] is False and r["error"] is None
    def blocked(cfg):
        r = by.get(cfg)
        return r is not None and r["blocked"] is True

    verdicts = []
    browser_cfgs = ["shell-headless", "shell-headless-spoofed",
                    "chromium-headed", "firefox-headless"]
    browsers_ok = all(ok(c) for c in browser_cfgs)
    everything_blocked = all(blocked(c) or by[c]["error"] for c in browser_cfgs)

    if browsers_ok:
        verdicts.append("No browser configuration was blocked - nothing to"
                        " attribute at this vantage point.")
    if blocked("plain-http") and not blocked("plain-http-chrome"):
        verdicts.append("HTTP layer: the raw client was blocked until browser"
                        " headers were added - a header-based gate (or a"
                        " TLS/client fingerprint check) in front of the site.")
    if blocked("plain-http") and blocked("plain-http-chrome") and ok("shell-headless"):
        verdicts.append("HTTP layer: both raw clients are blocked while real"
                        " browsers pass - the gate is below the headers"
                        " (TLS fingerprint or IP reputation), not UA sniffing.")
    if blocked("shell-headless") and ok("shell-headless-spoofed"):
        verdicts.append("Header level: patching UA + sec-ch-ua lifted the block"
                        " - the HeadlessChrome tokens were the trigger"
                        " (the dominant cause in arXiv:2606.14525).")
    if blocked("shell-headless") and blocked("shell-headless-spoofed") \
            and ok("chromium-headed"):
        verdicts.append("JS environment level: spoofed headers did not help but"
                        " headed Chromium passes - the trigger is the page-side"
                        " environment (navigator.webdriver, window.chrome,"
                        " plugins, CDP artifacts), not the headers.")
    browser_lab_blocked = all(by[c].get("lab_block") for c in browser_cfgs if c in by)
    if browser_lab_blocked:
        verdicts.append("JS environment level: the in-page check flagged every"
                        " browser configuration, headed included -"
                        " navigator.webdriver is true in all Playwright"
                        " conditions, so headful automation is not a human"
                        " baseline.")
        verdicts.append("Note: raw HTTP clients passed with HTTP 200 - they"
                        " never execute the page script, so a JS-layer block"
                        " is invisible without a browser (the study's"
                        " content-degradation blind spot).")
    if blocked("chromium-headed") and not browser_lab_blocked:
        verdicts.append("Deepest layer: even headed Chromium with a residential"
                        " display path was blocked - suspect IP reputation,"
                        " TLS fingerprinting, or deep JS/behavioral detection.")
    if blocked("firefox-headless") != blocked("shell-headless"):
        verdicts.append("Engine asymmetry: Chromium and Firefox headless were"
                        " treated differently - Client Hints absence on Firefox"
                        " changes the header surface a defender can score.")
    if not verdicts:
        verdicts.append("No differential pattern detected - inspect the raw"
                        " results table.")
    return verdicts


def print_report(url, results, verdicts):
    print(f"\n=== {url}")
    print(f"{'config':<24} {'status':<8} {'blocked':<8} {'vendor':<18} note")
    for r in results:
        note = ""
        if r["ua"] and "HeadlessChrome" in str(r["ua"]):
            note = "UA carries HeadlessChrome"
        elif r.get("webdriver") is True:
            note = "navigator.webdriver = true"
        if r["error"]:
            note = (r["error"][:60])
        elif r.get("lab_reasons"):
            note = f"in-page JS block: {r['lab_reasons']}"
        status = r["status"] if r["status"] is not None else "ERR"
        print(f"{r['config']:<24} {str(status):<8} {str(r['blocked']):<8} "
              f"{str(r['vendor'] or '-'):<18} {note}")
    print("  attribution:")
    for v in verdicts:
        print(f"   - {v}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("urls", nargs="+")
    parser.add_argument("--proxy", default=None,
                        help="socks5://user:pass@host:port applied to every config")
    parser.add_argument("--display", default=None,
                        help="X display for the headed run, e.g. :0")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--json", dest="json_out", default=None)
    args = parser.parse_args()

    all_out = {}
    for url in args.urls:
        results = run_all_configs(url, args)
        verdicts = attribute(results)
        print_report(url, results, verdicts)
        all_out[url] = {"results": results, "verdicts": verdicts}

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(all_out, fh, indent=2)
        print(f"\n[raw results written to {args.json_out}]")


if __name__ == "__main__":
    main()
