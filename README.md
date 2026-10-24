<p align="center">
  <img src="scopewatch.svg" alt="ScopeWatch logo" width="132" />
</p>

<h1 align="center">ScopeWatch</h1>

<p align="center">A calm, bounded snapshot of a website's public security posture.</p>

ScopeWatch is a small Python command-line tool for teams checking websites they own or are authorized to assess. It reads a single origin and reports a few visible configuration signals: HTTPS and certificate expiry, common response headers, cookie attributes, `robots.txt`, `security.txt`, and lightweight platform hints.

It is deliberately passive. It sends at most four fixed-path `GET` requests, does not follow links or redirects, does not submit forms, and does not attempt exploits or authentication. It uses only the Python standard library.

## Quick start

Requires Python 3.10 or newer.

```bash
python -m pip install .
scopewatch https://example.com --authorized
```

Create a JSON or Markdown report:

```bash
scopewatch https://example.com --authorized --format json --output report.json
scopewatch https://example.com --authorized --format markdown --output report.md
```

For a private lab you own, opt in explicitly:

```bash
scopewatch http://127.0.0.1:8080 --authorized --allow-private
```

Without installation, run from the project root:

```bash
python scopewatch_cli.py https://example.com --authorized
```

## What it checks

| Area | Signals |
|---|---|
| Transport | HTTP versus HTTPS, TLS certificate expiry |
| Browser-facing headers | HSTS, CSP, framing restrictions, MIME sniffing, referrer and permissions policies |
| Cookies | `Secure`, `HttpOnly`, and `SameSite` flags on observed cookies |
| Contact and discovery | `security.txt` and `robots.txt` presence |
| Platform | A small set of non-invasive public HTML and header hints |

Findings are prompts for human review, not proof of exploitability or a compliance certification. Header policies depend on the application and should be tested before rollout.

## Safety boundaries

- Assess only websites you own or have written permission to assess.
- One origin per run; no domain discovery or subdomain enumeration.
- Four fixed paths, one request per path, serially, with a capped response body and a bounded timeout.
- Redirect responses are recorded as responses; their destinations are never contacted.
- DNS results must be public unless `--allow-private` is explicitly supplied for a controlled lab.
- No payloads, exploit checks, brute force, port scans, shell access, or state-changing requests.
- Do not place credentials or session tokens in the target URL.

## How it works

1. Normalize the supplied origin and reject paths, queries, fragments, and embedded credentials.
2. Resolve its address and check that it is public, unless the user opts into private lab targets.
3. Pin requests to the resolved address while retaining hostname-based TLS verification.
4. Fetch only `/`, `/robots.txt`, `/.well-known/security.txt`, and `/security.txt` using bounded `GET` requests.
5. Turn observed response metadata into a text, Markdown, or JSON report. The homepage body is used only for a few local platform hints and is never included in the report.

## Development

The project has no runtime dependencies. Install an editable copy with `python -m pip install -e .` and run it with `scopewatch --help`.

## License

MIT. See [LICENSE](LICENSE).

