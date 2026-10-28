# Detecting the Detection - differential blocking attribution PoC

Companion PoC for the Hunt-Benito article "Detecting the Detection:
Finding Out Which Signal Blocked Your Scraper".

When a site blocks your scraper, five different signal layers could have
triggered it: IP reputation, TLS/HTTP-2 fingerprint, HTTP headers, the
JavaScript environment, or behavioral analysis. Guessing which one is
how afternoons disappear. This toolkit runs one URL through client
configurations that differ in exactly one layer at a time and prints an
attribution verdict - a miniature of the methodology from
[arXiv:2606.14525](https://arxiv.org/abs/2606.14525) (Gundelach,
Muehlhauser, Herrmann; University of Bamberg), which measured 10,000
sites this way.

## Scripts

| Script | What it does |
|---|---|
| `01_headers_exposed.py` | Local echo server + four browser configs: shows exactly what each announces in its HTTP headers (the confession table) |
| `02_probe.py` | The differential prober: six configurations per URL, soft-block detection (403/429/503), vendor signatures, attribution verdict |
| `03_honeypot.py` | Plants automation-framework honeypots (`window._selenium`, `callPhantom`, ...) and logs every access, including the probing script |
| `04_detection_lab.py` | A local stand-in detection vendor with three enforcement layers (`off` / `header` / `js`) for deterministic validation |

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install playwright httpx
playwright install chromium chromium-headless-shell firefox
```

The headed configuration needs a display: run on a desktop machine, or
under `xvfb-run` on a server:

```bash
xvfb-run -a python 02_probe.py http://127.0.0.1:8980/ --display :99
```

## Quick start

Terminal 1 - start the lab in header-block mode:

```bash
python 04_detection_lab.py --mode header
```

Terminal 2 - run the differential probe against it:

```bash
python 02_probe.py http://127.0.0.1:8980/
```

Expected: the default Playwright headless shell gets 403, the same shell
with UA + sec-ch-ua patched to headed values passes, headed passes - the
verdict reads "Header level". Repeat with `--mode js` to see the next
layer down: every configuration flagged by `navigator.webdriver`, headed
included, while raw HTTP clients sail through because they never run
page JavaScript.

Then watch the honeypots trip against the js lab:

```bash
python 03_honeypot.py http://127.0.0.1:8980/
```

## Reading the verdicts

| Verdict | Meaning |
|---|---|
| Header level | Patching UA + sec-ch-ua lifted the block - the HeadlessChrome tokens were the trigger |
| JS environment level | Headers were clean and it still blocked - `navigator.webdriver`, `window.chrome`, plugins, CDP artifacts |
| Deepest layer | Even headed Chromium blocked - IP reputation, TLS fingerprinting, or deep JS/behavioral detection |
| Engine asymmetry | Chromium and Firefox treated differently - Client Hints absence changes the scorable surface |

## Real-world usage

Point it at targets you own or have permission to test. Third-party
sites change their minds between requests: the article shows the same
configuration scoring 200 and 403 from the same IP minutes apart, which
is exactly why the study runs paired conditions in one time window.
Treat single-shot results as anecdote, not attribution.

The IP leg: `--proxy https://user:pass@proxy:port` runs the raw-client
configurations through a different exit. Chromium does not support
authenticated HTTPS or SOCKS5 proxies through Playwright's proxy option
(`ERR_PROXY_AUTH_UNSUPPORTED` / `ERR_SOCKS_CONNECTION_FAILED`) - chain a
local unauthenticated forwarder if you need browser configs through an
authenticated proxy.

## Versions used for the article runs

- Python 3.12, Playwright 1.64.1, httpx 0.28.1
- Chromium 156.0.8078.4 (shell + full binary), Firefox 157.0
- Vantage: UK residential ISP IP, October 28, 2026

## Ethics

Single-page visits, no interaction, targets you own or public test
pages. The goal is understanding your own blocking, not evading anyone's
defenses at scale.
