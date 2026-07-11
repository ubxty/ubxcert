# ubxcert

> **Modern, dependency-free ACME v2 / Let's Encrypt CLI.**  
> Built as a resilient, resumable alternative to certbot — pure PHP, no Python, no bloat.

[![PHP ≥ 8.1](https://img.shields.io/badge/PHP-%3E%3D8.1-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![ACME v2](https://img.shields.io/badge/ACME-v2%20RFC%208555-0095D5)](https://tools.ietf.org/html/rfc8555)
[![Let's Encrypt](https://img.shields.io/badge/Let's%20Encrypt-compatible-003A70)](https://letsencrypt.org/)
[![License MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What's new in v1.2.0

- **HTTP-01 single domains are now fully automatic.** `ubxcert request` defaults to
  `request → complete → install` in one shot — issue a cert and install it on the
  active web server with a single command. Pass `--no-auto` to preview the
  challenge values and finish by hand.
- **Smart `--challenge` default.** HTTP-01 is selected for non-wildcard domain lists;
  DNS-01 is forced only when a wildcard (`*.`) is present.
- **Webserver auto-detected** for the install step — the webserver that owns the
  domain's vhost docroot wins, falling back to the first running service detected
  by `systemctl`. Override with `--install-webserver`.
- v1.1.0 HTTP-01 auto-webroot remains: nginx, openresty, apache, caddy, litespeed,
  lighttpd, and nginx-unit are all auto-detected and the challenge file is
  written/probed for you.

```bash
sudo ubxcert request --domains "example.com" --email admin@example.com
# Done. Cert issued, installed, webserver reloaded.
```

---

## Why ubxcert?

| Feature | ubxcert | certbot |
|---|---|---|
| Language | Pure PHP 8.1+ | Python 3 + deps |
| Zero non-PHP dependencies | ✅ | ❌ |
| ACME v2 / RFC 8555 | ✅ | ✅ |
| Wildcard certs (DNS-01) | ✅ | ✅ |
| Single-domain certs (HTTP-01) | ✅ — no DNS work needed | ✅ |
| Default auto-chain (HTTP-01, v1.2.0+) | ✅ — `request → complete → install` in one command | ❌ |
| HTTP-01 auto-webroot (v1.1.0+) | ✅ — seven webservers supported¹ | partial |
| Two-step resumable flow | ✅ | ❌ |
| Certbot drop-in symlinks | ✅ — `/etc/letsencrypt/live/` | native |
| Interactive wizard | ✅ | ❌ |
| Health check (`doctor`) | ✅ | ❌ |
| Migrate certbot certs | ✅ | n/a |
| Idempotent delete | ✅ | ❌ (errors if missing) |
| JSON output on every command | ✅ | partial |
| Built-in self-updater | ✅ — `ubxcert update` | external |

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
# Friendly alias — checks for updates and asks "Update now? [y/N]"
# on a real TTY before installing. Defaults to N on non-TTY.
sudo ubxcert update

# Peek first, no install.
sudo ubxcert update --check
# → "New version available: v1.2.0" / "You are up-to-date."

# Skip the prompt (for automation / non-interactive shells).
sudo ubxcert update --yes

# Canonical command — same behavior, no prompt ever.
sudo ubxcert self-update
sudo ubxcert self-update --check

# Confirm after applying.
ubxcert --version
```

If the installed binary is older than v1.0.0 and does not yet include
`self-update`, re-run the one-liner installer to bring it forward — see
[Upgrading from an older ubxcert](#upgrading-from-an-older-ubxcert) below.

---

### Upgrading from an older ubxcert

Three paths, depending on what the box has today.

#### Path 1 — installed via `install-ubxcert.sh` (most common)

Any box where the original install ran the one-liner already has
`/opt/ubxcert/.git`, which means `self-update` can fast-path to
`git pull --ff-only` + `composer install --no-dev` without
re-downloading anything. Just SSH in and run:

```bash
sudo ubxcert update            # y/N prompt on a TTY
sudo ubxcert update --yes       # skip prompt
sudo ubxcert update --check     # peek, no install
```

State under `/etc/ubxcert/` and the auto-renewal cron job are
preserved across the upgrade. After the update, `ubxcert --version`
should report `v1.2.0`.

#### Path 2 — old binary that predates `self-update`

Boxes installed before `self-update` shipped (any v0.x or very early
v1.0.0) don't have the subcommand at all — `ubxcert self-update` will
print `ubxcert: unknown command 'self-update'`. Re-run the installer
from the main branch to bring the binary forward:

```bash
curl -fsSL https://raw.githubusercontent.com/ubxty/ubxcert/main/install-ubxcert.sh | sudo bash
```

The installer always pulls the latest main branch (not a tagged
release), so this gives you v1.2.0 immediately. After it finishes,
`sudo ubxcert update` works for future upgrades.

#### Path 3 — dev box installed via the `git@infoubx` path-repo

Developer / CI boxes where `ubxcert` was installed by cloning
`git@infoubx:ubxty/ubxcert.git` rather than the public installer also
have `/opt/ubxcert/.git`, but the remote points at the internal
infoubx host. `self-update` from those boxes will try to pull from
`git@infoubx` rather than GitHub — which is fine for development but
will fail on production boxes that lack SSH access to `git@infoubx`.

For production boxes that ended up in this state, point the remote
at GitHub and rebase:

```bash
sudo git -C /opt/ubxcert remote set-url origin \
  https://github.com/ubxty/ubxcert.git
sudo git -C /opt/ubxcert fetch origin
sudo git -C /opt/ubxcert reset --hard origin/main
sudo composer install -d /opt/ubxcert --no-dev --optimize-autoloader
```

After that, `sudo ubxcert update` works normally.

---

## Quick Start

### Default — one command, fully automatic

For a single-domain certificate on a server with a running nginx / openresty / apache, this is the entire flow:

```bash
sudo ubxcert request --domains "example.com" --email admin@example.com
```

Under the hood:

1. `--challenge http` is selected automatically (no `*.` in the domain list).
2. The active web server is detected (`nginx → openresty → apache → caddy → litespeed → lighttpd → nginx-unit`).
3. The site's document root is resolved from the vhost config.
4. The ACME challenge file is written to `<docroot>/.well-known/acme-challenge/<token>` and probed on the public URL.
5. `complete` polls the endpoint, finalizes the order, and downloads the cert to `/etc/ubxcert/certs/example.com/`.
6. `install` injects `ssl_certificate` / `ssl_certificate_key` directives into the vhost and reloads the server.

### Wildcard — DNS-01

```bash
ubxcert request --domains "*.example.com,example.com" --email admin@example.com
```

`--challenge dns` is selected automatically because the list contains a wildcard. The order is created and the DNS TXT records are printed. **Add them to your DNS provider (Cloudflare, cPanel, etc.)**, then finish the chain:

```bash
ubxcert complete --domain example.com --wait-dns 600
ubxcert install  --domain example.com --webserver openresty|nginx|apache
```

The auto-chain does **not** run for DNS-01 — adding TXT records requires manual work in your DNS provider, and no DNS provider integration is in scope for v1.2.0.

### Opt out — preview / step-by-step

```bash
ubxcert request --domains "example.com" --email admin@example.com --no-auto
# → prints HTTP-01 challenge body; finish manually:
ubxcert complete --domain example.com --wait-http 60
ubxcert install  --domain example.com --webserver openresty
```

Use `--no-auto` when you want to preview the challenge value or finish the chain by hand. To skip the auto-webroot write entirely (useful behind a CDN or when an external process owns `/.well-known/`), add `--no-auto-webroot` or set `--webroot=/path` to a custom staging directory. See [HTTP-01 Single-Domain Certificates](#http-01-single-domain-certificates).

### Inspect + renew

```bash
ubxcert list        # all certs (ubxcert + certbot) with expiry
ubxcert renew --all # auto-renewal loop; daily via /etc/cron.d/ubxcert-renew
```

---

## Interactive Wizard

For a guided setup that picks the site for you (detects the web server, lists vhosts with SSL status, and drives the issue+install chain):

```bash
ubxcert wizard                # interactive, picks a vhost, issues + installs the cert
ubxcert wizard --staging      # safe dry-run against LE staging
```

The wizard is most useful when you have multiple vhosts and don't want to look up which domain maps where — for a one-off `request` against a known domain, the bare command above is faster.

---

## Command Reference

| Command | Description |
|---|---|
| `request` | Create ACME order; chain `complete` + `install` by default for HTTP-01 |
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
# Default — issues the cert AND installs it on the active web server
ubxcert request --domains "example.com" --email admin@example.com

# Wildcard cert (DNS-01 auto-selected because of the *. )
ubxcert request --domains "*.example.com,example.com" --email admin@example.com

# Manual / preview (opt out of the auto-chain)
ubxcert request --domains "example.com" --email admin@example.com --no-auto
```

| Option | Description |
|---|---|
| `--domains` | Comma-separated list (wildcards only valid with `--challenge dns`) |
| `--email` | ACME account email |
| `--challenge` | Default = `http` when no domain is a wildcard, `dns` otherwise. Override with `dns` or `http`. |
| `--no-auto` | Opt out of the default `request → complete → install` chain. Prints the challenge values; finish with `complete` + `install` by hand. |
| `--install-webserver` | Force the install step to use `openresty` \| `nginx` \| `apache`. Default = the webserver that owns the domain's vhost docroot, falling back to the first running web server. |
| `--wait-http N` | Override the HTTP-01 polling timeout in the auto-chain (default: `120`). Env: `UBXCERT_AUTO_WAIT_HTTP`. |
| `--wait-dns N` | Override the suggested DNS-01 polling window printed for the manual `complete` step (default: `600`). Env: `UBXCERT_AUTO_WAIT_DNS`. |
| `--auto-webroot` | *(default for HTTP-01)* auto-detect the webserver + docroot, write `/.well-known/acme-challenge/<token>`, and verify reachability. |
| `--no-auto-webroot` | Print HTTP-01 challenges only; do not write to the docroot. Useful behind a CDN or when an external process owns the well-known path. |
| `--webroot=DIR` | Override the auto-detected docroot (or supply one when `--no-auto-webroot` is set). |
| `--force` | Discard any existing pending order and create a fresh one. |
| `--staging` | Use Let's Encrypt staging (no rate limits, fake cert). |
| `--json` | Output challenge data as JSON. With the auto-chain on, the envelope contains an `auto_chain` block summarising `complete` + `install`. |

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

A script-side caller (with `--no-auto`) writes `key_authorization` to that file path before invoking `ubxcert complete`.

**Behaviour:** `request` first registers (or reuses) a Let's Encrypt account for `--email`, creates the ACME order, computes the challenge values, persists order state to `/etc/ubxcert/orders/<domain>/state.json`, and:

- For HTTP-01 single domains: serves the challenge file at the detected docroot, polls the public URL, finalises the order, downloads the cert, and installs it into the detected vhost + reloads.
- For DNS-01 / wildcards: prints the `_acme-challenge.<domain>` TXT records. The auto-chain stops here (no DNS provider integration is in scope for v1.2.0).

### `ubxcert complete`

```
ubxcert complete --domain example.com
ubxcert complete --domain example.com --wait-http 60          # HTTP-01
ubxcert complete --domain example.com --wait-dns  600         # DNS-01
```

`request` invokes `complete` automatically for HTTP-01 single domains. You only need to run it by hand when you used `--no-auto` or are completing a DNS-01 order.

| Option | Description |
|---|---|
| `--domain` | Base domain (must match the one used in `request`) |
| `--challenge` | Override challenge type detection (`dns` or `http`). Usually inferred from the saved order state. |
| `--wait-dns` | Seconds to poll DNS for TXT propagation (default: `0` — no wait, ACME validates on trigger). DNS-01 only. |
| `--wait-http` | Seconds to poll `http://<domain>/.well-known/acme-challenge/<token>` (default: `0` — no wait). HTTP-01 only. |
| `--auto-webroot` / `--no-auto-webroot` | Same semantics as on `request`. |
| `--webroot=DIR` | Override the detected docroot. |
| `--staging` | Must match the flag used in `request`. |
| `--json` | Output cert details as JSON. |

Files created: `/etc/ubxcert/certs/<domain>/{cert,chain,fullchain,privkey}.pem`  
Symlinks: `/etc/letsencrypt/live/<domain>/` → same files (certbot compat)

### `ubxcert install`

```
ubxcert install --domain example.com --webserver openresty
ubxcert install --domain example.com --webserver nginx --conf /etc/nginx/sites-available/mysite.conf
ubxcert install --domain example.com --webserver apache --conf /etc/apache2/sites-available/mysite-le-ssl.conf
```

`request` invokes `install` automatically for HTTP-01 single domains. You only need to run it by hand when you used `--no-auto`, are reinstalling into a different webserver, or your vhost config isn't at the default path.

| Option | Description |
|---|---|
| `--domain` | Domain whose certificate to install |
| `--webserver` | `openresty` \| `nginx` \| `apache` |
| `--conf` | Override the vhost config path (auto-detected by default) |

Default config paths:

- openresty: `/usr/local/openresty/nginx/conf/sites-available/<domain>.conf`
- nginx: `/etc/nginx/sites-available/<domain>.conf`
- apache: `/etc/apache2/sites-available/<domain>-le-ssl.conf`

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

### Auto mode (default, v1.2.0+)

This is the recommended path — `ubxcert request` does everything end-to-end (request → complete → install) in a single command:

```bash
sudo ubxcert request \
  --domains "example.com" \
  --email admin@example.com

# Equivalent in older releases was the two-step form:
#   ubxcert request  --domains "example.com" --email admin@example.com --challenge http
#   ubxcert complete --domain example.com --challenge http --wait-http 60
#   ubxcert install  --domain example.com --webserver openresty|nginx|apache
```

What `request` does behind the scenes for HTTP-01 single domains:

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
5. Polls the endpoint (`--wait-http 120` by default) until ACME validates,
   then finalises the order and downloads the cert chain.
6. Injects `ssl_certificate` / `ssl_certificate_key` into the vhost and
   reloads the web server.

You should see something like:

```
✓ HTTP-01 auto-served: /var/www/example.com/.well-known/acme-challenge/<token>
  (verified at http://example.com/.well-known/acme-challenge/<token>)
--- Auto-chain: complete ---
✓ HTTP-01 reachable for example.com
✓ All challenges validated.
✓ Certificate issued and saved!
--- Auto-chain: install ---
  webserver : openresty
✓ OpenResty config test passed.
✓ OpenResty reloaded.
✓ Auto-chain complete: cert installed on openresty for example.com.
```

If auto-webroot verification fails, the file is still in place — the operator can
retry the install step once port 80 / DNS is fixed:

```bash
sudo ubxcert install --domain example.com --webserver openresty
```

Override the auto-detected docroot with `--webroot=/srv/www/staging`; force a
specific webserver with `--install-webserver nginx`; opt out of the entire chain
with `--no-auto`.

### Manual mode (`--no-auto`)

Use `--no-auto` when you want to preview the challenge value, finish the
chain by hand, or run only one of the steps for a retry.

```bash
# Print the challenge values and stop.
ubxcert request --domains "example.com" --email admin@example.com --no-auto

# Then run complete + install only after the operator is ready.
ubxcert complete --domain example.com --wait-http 60
ubxcert install  --domain example.com --webserver openresty
```

To skip the auto-write of the challenge file entirely — useful behind a
CDN that intercepts port 80, when an external process owns the
`/.well-known/` path, or for template-generated vhosts that aren't
parseable — add `--no-auto-webroot` (or `--webroot=/path` to point at a
custom staging directory). The operator must serve the file manually:

```bash
# ubxcert writes the challenge body to JSON; serve it yourself.
ubxcert request \
  --domains "example.com" \
  --email admin@example.com \
  --challenge http \
  --no-auto-webroot \
  --json
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

Wildcards (`*.example.com`) always use DNS-01 because HTTP-01 cannot serve
wildcard identifiers (RFC 8555 §7.2). For single-domain wildcards, one cert
covers both `*.example.com` (all subdomains) and the bare `example.com`.

```bash
# 1. Request — prints the _acme-challenge TXT records.
ubxcert request \
  --domains "*.example.com,example.com" \
  --email admin@example.com

# 2. Add the _acme-challenge TXT records printed above to your DNS.

# 3. Complete — verifies DNS and downloads the cert.
ubxcert complete --domain example.com --wait-dns 600

# 4. Install — explicitly, because DNS-01 never auto-installs.
ubxcert install  --domain example.com --webserver openresty|nginx|apache
```

The auto-chain (`--no-auto` not set) still issues the order, but the chain
stops at `request` and prints a yellow note explaining the manual TXT-record
step. No DNS provider integration is in scope for v1.2.0.

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
  Installed : v1.2.0
  Latest    : v1.2.0

  You are up-to-date.
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
