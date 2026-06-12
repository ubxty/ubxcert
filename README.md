# ubxcert

> **Modern, dependency-free ACME v2 / Let's Encrypt CLI.**  
> Built as a resilient, resumable alternative to certbot — pure PHP, no Python, no bloat.

[![PHP ≥ 8.1](https://img.shields.io/badge/PHP-%3E%3D8.1-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![ACME v2](https://img.shields.io/badge/ACME-v2%20RFC%208555-0095D5)](https://tools.ietf.org/html/rfc8555)
[![Let's Encrypt](https://img.shields.io/badge/Let's%20Encrypt-compatible-003A70)](https://letsencrypt.org/)
[![License MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Why ubxcert?

| Feature | ubxcert | certbot |
|---|---|---|
| Language | Pure PHP 8.1+ | Python 3 + deps |
| Two-step resumable flow | ✅ | ❌ |
| Wildcard certs (DNS-01) | ✅ | ✅ |
| Single-domain certs (HTTP-01) | ✅ (no DNS work needed) | ✅ |
| ACME v2 RFC 8555 | ✅ | ✅ |
| Zero non-PHP dependencies | ✅ | ❌ |
| Certbot drop-in symlinks | ✅ — `/etc/letsencrypt/live/` | native |
| Interactive wizard | ✅ | ❌ |
| Health check (`doctor`) | ✅ | ❌ |
| Migrate certbot certs | ✅ | n/a |
| JSON output on every command | ✅ | partial |

---

## Requirements

| Item | Minimum |
|---|---|
| PHP | 8.1+ |
| PHP extensions | `openssl`, `curl`, `json` |
| DNS access | TXT record creation (manual or Cloudflare API) |
| OS | Linux (tested on Ubuntu 22.04 / CentOS 8) |
| Web server | nginx, openresty, or apache2 (optional — for auto-install) |

---

## Installation

### One-liner (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/ubxty/ubxcert/main/install-ubxcert.sh | sudo bash
```

### From local source

```bash
git clone git@infoubx:ubxty/ubxcert.git /opt/ubxcert
ln -sf /opt/ubxcert/bin/ubxcert /usr/local/bin/ubxcert
```

### Verify

```bash
ubxcert version
ubxcert doctor
```

---

## Quick Start

### 1 — Request a certificate

**Wildcard cert (DNS-01, default):**
```bash
ubxcert request \
  --domains "*.example.com,example.com" \
  --email admin@example.com
```
ubxcert prints DNS TXT challenge values — add them to your DNS provider (Cloudflare, cPanel, etc.).

**Single-domain cert (HTTP-01, faster, no DNS work):**
```bash
ubxcert request \
  --domains "example.com" \
  --email admin@example.com \
  --challenge http
```
ubxcert prints a `token` and `key_authorization`. Serve the `key_authorization` as the body of:
```
http://example.com/.well-known/acme-challenge/<token>
```
on the domain itself, port 80. Then run the `complete` step with `--challenge http --wait-http 60`.

### 2 — Complete the order (verify challenge + download cert)

```bash
# DNS-01 (wildcard or single-domain)
ubxcert complete --domain example.com --wait-dns 600

# HTTP-01 (single-domain only)
ubxcert complete --domain example.com --challenge http --wait-http 60
```

`--wait-dns 600` polls DNS up to 10 minutes. `--wait-http 60` polls the HTTP-01 endpoint up to 60 seconds. The certificate is saved to `/etc/ubxcert/certs/example.com/`.

### 3 — Install into your web server

```bash
ubxcert install --domain example.com --webserver openresty
# or nginx / apache
```

### 4 — Check all certificates

```bash
ubxcert list
```

### 5 — Renew automatically

```bash
ubxcert renew --all
```

Auto-renewal cron (installed by `install-ubxcert.sh`):

```
15 3 * * *  root  /usr/local/bin/ubxcert renew --all --days-before 30 >> /var/log/ubxcert/renew.log 2>&1
```

---

## Interactive Wizard

For a guided, step-by-step setup:

```bash
ubxcert wizard
```

The wizard:
1. Detects your running web server (nginx / openresty / apache)
2. Lists all configured virtual hosts with SSL status
3. Lets you pick a site by number or domain name
4. Asks for wildcard or single-domain cert
5. Runs `request`, pauses for you to add DNS TXT records, then runs `complete`
6. Optionally installs the cert into your web server

```bash
ubxcert wizard --staging   # safe dry-run against LE staging
```

---

## Command Reference

| Command | Description |
|---|---|
| `request` | Create ACME order; print challenge values (DNS-01 TXT or HTTP-01 file body) |
| `complete` | Verify challenge (DNS or HTTP), finalize order, download + save certificate |
| `install` | Inject cert into web server vhost and reload |
| `renew` | Renew one or all certs expiring within N days |
| `list` | List ALL certs (ubxcert + certbot), wildcard + server columns |
| `status` | Show order/challenge state for a single domain |
| `server` | Scan vhosts, detect web server, show SSL health per domain |
| `doctor` | Health check: PHP, extensions, binary, dirs, cron, cert health |
| `scan` | Diagnostic: list all vhost config files and parsed domains |
| `wizard` | Interactive TUI: detect server, pick site, issue + install cert |
| `migrate` | Migrate certbot-managed certs to ubxcert management |
| `self-update` | Update ubxcert to the latest version from GitHub |

All commands support `--help` and `--json`.

### `ubxcert request`

```
ubxcert request --domains "*.example.com,example.com" --email admin@example.com
ubxcert request --domains "site.com" --email admin@site.com --staging --force
ubxcert request --domains "site.com" --email admin@site.com --challenge http
```

| Option | Description |
|---|---|
| `--domains` | Comma-separated list (wildcard supported with `--challenge dns` only) |
| `--email` | ACME account email |
| `--challenge` | `dns` (default) or `http`. HTTP-01 is faster (no DNS propagation) but does not support wildcards. |
| `--force` | Discard existing pending order and start fresh |
| `--staging` | Use LE staging (no rate limits, fake cert) |
| `--json` | Output challenge data as JSON |

For `--challenge http`, the JSON output includes, per domain:

```json
{
  "challenge_type": "http-01",
  "token": "<server-issued token>",
  "key_authorization": "<token>.<account-thumbprint>",
  "http_url": "http://example.com/.well-known/acme-challenge/<token>",
  "challenge_path": "/.well-known/acme-challenge/<token>"
}
```

The script-side caller writes `key_authorization` to that file path before invoking `ubxcert complete`.

### `ubxcert complete`

```
ubxcert complete --domain example.com --wait-dns 600
ubxcert complete --domain example.com --challenge http --wait-http 60
```

| Option | Description |
|---|---|
| `--domain` | Base domain (must match the one used in `request`) |
| `--challenge` | Override challenge type detection (`dns` or `http`). Usually inferred from the saved order state. |
| `--wait-dns` | Seconds to poll DNS for TXT propagation (default: 0). DNS-01 only. |
| `--wait-http` | Seconds to poll `http://<domain>/.well-known/acme-challenge/<token>` (default: 0). HTTP-01 only. |
| `--staging` | Must match flag used in `request` |

Files created: `/etc/ubxcert/certs/<domain>/{cert,chain,fullchain,privkey}.pem`  
Symlinks: `/etc/letsencrypt/live/<domain>/` → same files (certbot compat)

### `ubxcert install`

```
ubxcert install --domain example.com --webserver openresty
ubxcert install --domain example.com --webserver nginx --conf /etc/nginx/sites-available/mysite.conf
```

Supported: `nginx`, `openresty`, `apache`

### `ubxcert renew`

```
ubxcert renew --all
ubxcert renew --all --days-before 45
ubxcert renew --all --cf-token $CF_TOKEN --cf-zone-id $CF_ZONE_ID --webserver nginx
```

| Option | Description |
|---|---|
| `--all` | Renew all managed domains expiring within `--days-before` |
| `--domain` | Renew a single domain |
| `--days-before` | Renewal window in days (default: 30) |
| `--cf-token` | Cloudflare API token for automated DNS-01 |
| `--cf-zone-id` | Cloudflare Zone ID (required with `--cf-token`) |
| `--webserver` | Web server to reload after renewal |

### `ubxcert list`

```
ubxcert list
ubxcert list --json
ubxcert list --certbot-only
```

Output columns: `DOMAIN | WC | SOURCE | SERVER | STATUS | EXPIRES | DAYS`

- **WC** — ★ if the cert covers a wildcard (`*.domain.com`)
- **SERVER** — webserver where SSL is actively installed (nginx/openresty/apache)
- Expiry colour-coded: green (healthy) → yellow (<30d) → red (<14d / expired)

### `ubxcert status`

```
ubxcert status --domain example.com
ubxcert status --domain example.com --json
```

Shows order status, email, pending DNS challenge values, and certificate expiry.

### `ubxcert server`

```
ubxcert server
ubxcert server --webserver nginx --live-check --json
```

Scans `sites-enabled/` + `conf.d/` directories, parses vhosts, cross-references certificates, prints a summary.

### `ubxcert doctor`

```
ubxcert doctor
ubxcert doctor --json
```

Checks performed:
- PHP version (≥ 8.1)
- PHP extensions: openssl, curl, json
- Binary: `/usr/local/bin/ubxcert`
- DNS tool: `dig`
- State directories: `/etc/ubxcert/{certs,orders,accounts}/`
- Log directory: `/var/log/ubxcert/`
- Auto-renewal cron: `/etc/cron.d/ubxcert-renew`
- Active web server
- Certificate health (expired / expiring in <30d)

Exit code 0 = healthy/warnings, 1 = critical.

### `ubxcert wizard`

Interactive step-by-step wizard — see [Interactive Wizard](#interactive-wizard) above.

### `ubxcert migrate`

```
ubxcert migrate --all
ubxcert migrate --domain example.com
ubxcert migrate --all --dry-run
ubxcert migrate --all --email admin@example.com
```

---

## Certbot Migration

Migrate existing certbot-managed certificates so `ubxcert renew --all` takes over:

```bash
# Preview (no files written)
ubxcert migrate --all --dry-run

# Run migration
ubxcert migrate --all --email your@email.com

# Verify
ubxcert list
ubxcert doctor
```

What happens per domain:
1. PEM files are copied from `/etc/letsencrypt/live/<domain>/` → `/etc/ubxcert/certs/<domain>/`
2. A minimal `state.json` is created so ubxcert can track + renew the cert
3. Symlinks in `/etc/letsencrypt/live/<domain>/` are updated to point at the ubxcert copies
4. certbot's archive is **not touched** — originals are safe

---

## HTTP-01 Single-Domain Certificates

For non-wildcard single-domain certs, HTTP-01 is faster than DNS-01: no DNS
record to add, no propagation delay, and no Cloudflare integration needed.
The trade-off is the server itself must serve the challenge file on port 80.

```bash
# 1. Request — ubxcert prints token + key authorization as JSON
ubxcert request --domains "example.com" --email admin@example.com --challenge http

# 2. Serve the key_authorization body at /.well-known/acme-challenge/<token>
#    on example.com (port 80). For example, with nginx:
#      location /.well-known/acme-challenge/ {
#          default_type "text/plain";
#          root /var/www/acme;
#      }
#    Then: echo "<key_authorization>" > /var/www/acme/.well-known/acme-challenge/<token>

# 3. Complete — ubxcert polls the URL up to 60s, then downloads the cert
ubxcert complete --domain example.com --challenge http --wait-http 60
```

Notes:
- HTTP-01 cannot be used for `*.example.com` wildcard certs (per RFC 8555).
  Wildcards always use DNS-01.
- The challenge is served over **HTTP** (port 80), not HTTPS — the ACME server
  follows the redirect from HTTPS to HTTP if needed.
- The exact file path matters: it must be
  `http://<domain>/.well-known/acme-challenge/<token>` and the file body must
  be the `key_authorization` string **verbatim**, with no trailing whitespace.

---

## Wildcard Certificates

```bash
ubxcert request \
  --domains "*.example.com,example.com" \
  --email admin@example.com

# Add the _acme-challenge TXT records shown, then:
ubxcert complete --domain example.com --wait-dns 600
```

One cert covers both `*.example.com` (all subdomains) and the bare `example.com`.

---

## File Layout

```
/etc/ubxcert/
├── accounts/
│   └── admin@example.com/
│       ├── account.json        # ACME account + KID
│       └── account.key         # RSA 4096 account key
├── orders/
│   └── example.com/
│       ├── state.json          # Order state (resumable)
│       └── cert.key            # Private key for this cert
└── certs/
    └── example.com/
        ├── cert.pem
        ├── chain.pem
        ├── fullchain.pem
        └── privkey.pem         # chmod 0600

/etc/letsencrypt/live/
└── example.com/                # symlinks → /etc/ubxcert/certs/example.com/
    ├── cert.pem -> ...
    ├── chain.pem -> ...
    ├── fullchain.pem -> ...
    └── privkey.pem -> ...

/var/log/ubxcert/
└── ubxcert.log                 # auto-rotates at 10 MB

/etc/cron.d/
└── ubxcert-renew               # daily auto-renewal
```

---

## Security Notes

- Private keys are stored with `chmod 0600` and directories with `chmod 0700`
- All ACME communication is over HTTPS
- JWS signed with RSA-4096
- Symlinks under `/etc/letsencrypt/live/` allow drop-in use with nginx/apache without any config changes
- Root access is required for writing to `/etc/ubxcert/` and `/etc/letsencrypt/`

---

## Global Flags

All commands accept:

| Flag | Description |
|---|---|
| `--staging` | Use Let's Encrypt staging environment |
| `--json` | Machine-readable JSON output |
| `--verbose` / `-v` | Show detailed ACME protocol steps |
| `--help` / `-h` | Show per-command help |

---

## Additional Commands

### `ubxcert scan`

```
ubxcert scan
ubxcert scan --json
```

Diagnostic tool — lists all vhost configuration files found in `sites-enabled/` and `conf.d/`, along with their parsed domain names. Useful for debugging why a domain is not appearing in `ubxcert server` or `ubxcert list`.

### `ubxcert self-update`

```
ubxcert self-update
ubxcert --version --check
```

Downloads and installs the latest release from GitHub. The `--version --check` flag compares the running version against the latest GitHub release without updating.

---

## License

MIT © [Ubxty](https://ubxty.com)

---

## Author

**Ravdeep Singh**  
Lead Developer, Ubxty  
[linkedin.com/in/ravdeep-singh-a4544abb](https://www.linkedin.com/in/ravdeep-singh-a4544abb/)  
[info.ubxty@gmail.com](mailto:info.ubxty@gmail.com)
