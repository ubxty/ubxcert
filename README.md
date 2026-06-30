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
| Single-domain certs (HTTP-01) | ✅ (no DNS work needed)¹ | ✅ |
| ACME v2 RFC 8555 | ✅ | ✅ |
| Zero non-PHP dependencies | ✅ | ❌ |
| Certbot drop-in symlinks | ✅ — `/etc/letsencrypt/live/` | native |
| Interactive wizard | ✅ | ❌ |
| Health check (`doctor`) | ✅ | ❌ |
| Migrate certbot certs | ✅ | n/a |
| Idempotent delete (`delete`) | ✅ | ❌ (errors if missing) |
| JSON output on every command | ✅ | partial |

¹ v1.1.0+ auto-serves the `/.well-known/acme-challenge/<token>` file across nginx, openresty, apache, caddy, litespeed, lighttpd, and nginx-unit — no manual `echo` needed.

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

### Updating an existing ubxcert

`ubxcert` ships with a built-in self-updater. The updater queries the
GitHub releases API for the latest tagged release and (if newer) replaces
`/opt/ubxcert` and `/usr/local/bin/ubxcert` in place. The auto-renewal
cron job and the state under `/etc/ubxcert/` are preserved.

```bash
# Check first — does not change anything.
sudo ubxcert self-update --check
# → "New version available: v1.1.0" / "You are up-to-date."

# Apply the update.
sudo ubxcert self-update

# Or use the friendly short alias — it asks "Update now? [y/N]"
# on a real TTY before installing (defaults to N if unsure).
sudo ubxcert update
sudo ubxcert update --yes    # skip the prompt

# Confirm
ubxcert --version
```

If the installed binary is older than v1.0.0 and does not yet include
`self-update`, re-run the one-liner installer to bring it forward:

```bash
curl -fsSL https://raw.githubusercontent.com/ubxty/ubxcert/main/install-ubxcert.sh | sudo bash
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
**v1.1.0+: ubxcert auto-detects the active web server (nginx, openresty,
apache, caddy, litespeed, lighttpd, or nginx-unit), finds the site's
document root, writes the challenge file, and verifies reachability from
the public internet.** No manual `echo`, no DNS dance.

Want to print the challenge and serve the file yourself instead? Use
`--no-auto-webroot` (or `--webroot=/path` to override detection) — see
[HTTP-01 Single-Domain Certificates](#http-01-single-domain-certificates)
below.

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
| `delete` | Delete a cert + its order state (idempotent; supports --all bulk) |
| `list` | List ALL certs (ubxcert + certbot), wildcard + server columns |
| `status` | Show order/challenge state for a single domain |
| `server` | Scan vhosts, detect web server, show SSL health per domain |
| `doctor` | Health check: PHP, extensions, binary, dirs, cron, cert health |
| `scan` | Diagnostic: list all vhost config files and parsed domains |
| `wizard` | Interactive TUI: detect server, pick site, issue + install cert |
| `migrate` | Migrate certbot-managed certs to ubxcert management |
| `self-update` | Update ubxcert to the latest version from GitHub |
| `update` | Short alias for `self-update` — interactive y/N prompt before installing |

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

### `ubxcert delete`

```
ubxcert delete --domain example.com
ubxcert delete --domain example.com --purge
ubxcert delete --domain example.com --keep-cert
ubxcert delete --all
ubxcert delete --all --purge --json
```

| Option | Description |
|---|---|
| `--domain` | Domain whose cert + state to remove |
| `--all` | Remove every domain found under `/etc/ubxcert/{certs,orders}/` |
| `--purge` | Also remove `/etc/letsencrypt/live/<domain>/` symlink dir and `renewal/<domain>.conf` |
| `--keep-cert` | Preserve cert files; only clear order state |
| `--keep-state` | Preserve order state; only remove cert files |
| `--certbot` | Also invoke `certbot delete --cert-name <domain>` (for legacy certbot-managed certs) |
| `--json` | Machine-readable JSON output |

**Behavior:** idempotent. Returns exit 0 when there's nothing to delete, so a script can call this without pre-checking existence. The JSON shape is:

```json
{
  "command": "delete",
  "domains": [{ "domain": ..., "cert_removed_count": N, "state_removed_count": N, "errors": [] }],
  "deleted_count": N,
  "noop_count": N,
  "succeeded": true
}
```

**Exit codes:** 0 = every domain either succeeded or was a no-op. 1 = validation error (missing args, conflicting flags) or unrecoverable error (unreadable dir, certbot missing with `--certbot`).

Use case: bulk cleanup after migration, or making a clean handoff back to certbot. The CloudPanzer panel's `permanent_delete_ssl.sh` calls this in lieu of `certbot delete` (which fails with "Certificate not found" when the cert is ubxcert-managed and not in certbot's store).

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

> HTTP-01 cannot be used for `*.example.com` wildcard certs (per RFC 8555
> §7.2). Wildcards always use DNS-01.
>
> The challenge is served over **HTTP** (port 80), not HTTPS — the ACME
> server follows a redirect from HTTPS to HTTP if needed.
>
> The exact file path matters: it must be
> `http://<domain>/.well-known/acme-challenge/<token>` and the file body
> must be the `key_authorization` string **verbatim**, with no trailing
> whitespace.

### Auto mode (default, v1.1.0+)

The recommended path — ubxcert does everything end-to-end:

```bash
# 1. Request — ubxcert detects the webserver, finds the docroot,
#    writes the challenge file, and verifies reachability.
ubxcert request \
  --domains "example.com" \
  --email admin@example.com \
  --challenge http

# 2. Complete — same as before; ubxcert re-writes the file idempotently
#    if needed and cleans it up automatically once the cert is issued.
ubxcert complete \
  --domain example.com \
  --challenge http \
  --wait-http 60
```

What `request` does for HTTP-01:

1. Auto-detects the running webserver via `systemctl` (priority order:
   nginx → openresty → apache → caddy → litespeed → lighttpd → nginx-unit).
2. Scans the webserver's enabled vhost configs and parses the matching
   `root` (nginx/openresty), `DocumentRoot` (apache/litespeed),
   `root *` (caddy), `server.document-root` (lighttpd), or
   `applications.<name>.root` (nginx-unit) to find the document root.
3. Creates `<docroot>/.well-known/acme-challenge/<token>` with the
   `key_authorization` body, mode 0644.
4. Probes `http://<domain>/.well-known/acme-challenge/<token>` from the
   public internet and confirms the body roundtrips exactly.

You should see something like:

```
✓ HTTP-01 auto-served: /var/www/example.com/.well-known/acme-challenge/<token>
  (verified at http://example.com/.well-known/acme-challenge/<token>)
```

If verification fails, the file is still in place — the operator can
retry with `ubxcert complete --wait-http 60` once port 80 / DNS is fixed.

Override the auto-detected docroot with `--webroot=/srv/www/staging`, or
opt out entirely with `--no-auto-webroot`.

### Manual mode (`--no-auto-webroot`)

Useful when:

- You're behind a CDN that intercepts port 80 (Cloudflare orange-clouded,
  CloudFront, Fastly) — the ACME server will fetch from the origin, and
  the origin needs to serve from a custom staging directory.
- A separate process (auth service, reverse proxy) owns the
  `/.well-known/` path on the domain.
- The webserver config is intentionally not parseable (template-generated,
  immutable image, etc.).

```bash
# Print the challenge values as JSON; serve the file yourself.
ubxcert request \
  --domains "example.com" \
  --email admin@example.com \
  --challenge http \
  --no-auto-webroot

# Or: let ubxcert write the file but to a directory you specify.
ubxcert request \
  --domains "example.com" \
  --email admin@example.com \
  --challenge http \
  --webroot=/var/www/acme-staging

# Serve the key_authorization body at:
#   http://example.com/.well-known/acme-challenge/<token>
# Then complete as normal:
ubxcert complete --domain example.com --challenge http --wait-http 60
```

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "File written but ACME server could not reach it from outside" | Port 80 blocked by firewall / security group | Open TCP 80 inbound for `0.0.0.0/0` temporarily for issuance |
| "a different body is being served" | Default-server vhost is intercepting `/.well-known/` | Add `location = /.well-known/acme-challenge/{token} { default_type text/plain; }` to the correct vhost |
| "could not detect a document root" | No vhost config matches the domain; webserver not running | Point `server_name` at the domain in the vhost, then rerun; or pass `--webroot=/path` |
| `body` mismatch, 200 OK | Webserver is rewriting/gzipping responses | Confirm with `curl -v http://example.com/.well-known/acme-challenge/<token>` directly |
| Cert still fails after `--wait-http 60` | DNS not propagated yet (new domain) | Wait, then rerun `ubxcert complete --wait-http 60`; the file remains in place |

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

### `ubxcert update`

```
ubxcert update          # check + interactive y/N prompt
ubxcert update --yes    # skip prompt, apply if newer
ubxcert update --check  # print version info only
```

Short alias for `self-update`. The only difference is that when a newer
release is detected on a real TTY, this command asks before installing:

```
  ubxcert version check
  ────────────────────────────────────────────
  Installed : v1.0.0
  Latest    : v1.1.0

  A new version is available: v1.1.0 (current v1.0.0).
  Update now? [y/N] _
```

The prompt is **silently skipped** in non-interactive contexts (cron,
piped output, no TTY) — pass `--yes` to force-apply. `--check`,
`--force`, `--verbose`, and `--json` all pass through to `self-update`.

---

## License

MIT © [Ubxty](https://ubxty.com)

---

## Author

**Ravdeep Singh**  
Lead Developer, Ubxty  
[linkedin.com/in/ravdeep-singh-a4544abb](https://www.linkedin.com/in/ravdeep-singh-a4544abb/)  
[info.ubxty@gmail.com](mailto:info.ubxty@gmail.com)
