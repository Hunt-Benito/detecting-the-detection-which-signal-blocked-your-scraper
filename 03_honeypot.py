#!/usr/bin/env python3
"""Step 3 of the walkthrough: automation honeypots.

Plants properties on window/document that only automation-framework
probing would ever touch (window._selenium, callPhantom, domAutomation, ...)
and logs every access, including the script that performed it - the same
trick the Bamberg study used to find that 46% of the Tranco Top 10K probe
for at least one automation artifact (arXiv:2606.14525, Section 5.4).

Legitimate pages have no reason to read any of these names: an access is a
detection attempt, full stop (the paper's "Tier 1" signals).

Usage:
    python 03_honeypot.py URL [--timeout 30]
"""

import argparse
import json
import re

INIT_SCRIPT = """
(() => {
  const names = [
    '_selenium', 'callSelenium', '_Selenium_IDE_Recorder',
    '__selenium_unwrapped', '__webdriver_evaluate', '__driver_evaluate',
    '__fxdriver_evaluate', '__webdriver_script_fn', '__webdriver_script_result',
    '_phantom', '__phantom_vars', 'callPhantom', '_nightmare', '__nightmare',
    'domAutomation', 'domAutomationController', '__driver_unwrapped',
  ];
  window.__hp_hits = [];
  const plant = (obj, key) => {
    try {
      Object.defineProperty(obj, key, {
        configurable: false,
        get() {
          const stack = (new Error().stack || '').split('\\n').slice(2, 7).join(' | ');
          window.__hp_hits.push({name: key, stack});
          return undefined;
        }
      });
    } catch (e) { /* non-configurable or missing object - skip */ }
  };
  for (const n of names) plant(window, n);
  for (const n of ['__selenium_unwrapped', '__webdriver_evaluate',
                   '__driver_evaluate', '_phantom']) plant(document, n);
})();
"""

FAMILIES = {
    "selenium": ["_selenium", "callSelenium", "_Selenium_IDE_Recorder",
                 "__selenium_unwrapped", "__webdriver_evaluate",
                 "__driver_evaluate", "__fxdriver_evaluate",
                 "__webdriver_script_fn", "__webdriver_script_result",
                 "__driver_unwrapped"],
    "phantomjs": ["_phantom", "__phantom_vars", "callPhantom"],
    "nightmarejs": ["_nightmare", "__nightmare"],
    "webdriver protocol": ["domAutomation", "domAutomationController"],
}


def family_of(name):
    for family, members in FAMILIES.items():
        if name in members:
            return family
    return "?"


def script_urls(stack):
    return re.findall(r"https?://[^)\s]+", stack or "")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        context.add_init_script(INIT_SCRIPT)
        page = context.new_page()
        print(f"[*] visiting {args.url} with 17 honeypots planted")
        page.goto(args.url, timeout=args.timeout * 1000,
                  wait_until="domcontentloaded")
        page.wait_for_timeout(4000)
        hits = page.evaluate("window.__hp_hits || []")
        browser.close()

    if not hits:
        print("[*] no honeypot was touched during the visit")
        return

    counts = {}
    probers = set()
    for hit in hits:
        name = hit["name"]
        counts[name] = counts.get(name, 0) + 1
        for u in script_urls(hit.get("stack", "")):
            probers.add(u.split("/")[2])

    print(f"[*] {len(hits)} honeypot accesses detected\n")
    print(f"{'property':<28} {'accesses':<10} family")
    for name, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"{name:<28} {count:<10} {family_of(name)}")
    if probers:
        print(f"\n[*] scripts doing the probing: {', '.join(sorted(probers))}")
    print("\nan access to any of these names has no legitimate purpose -")
    print("the page (or a third-party detection script) was checking whether")
    print("an automation framework is driving this browser.")


if __name__ == "__main__":
    main()
