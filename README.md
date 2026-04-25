# ubxcert

> A modern, dependency-free ACME v2 / Let's Encrypt CLI — built as a resilient, resumable replacement for certbot.

[![PHP ≥ 8.1](https://img.shields.io/badge/PHP-%3E%3D8.1-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![ACME v2](https://img.shields.io/badge/ACME-v2%20RFC%208555-blue)](https://tools.ietf.org/html/rfc8555)
[![Let's Encrypt](https://img.shields.io/badge/Let's%20Encrypt-supported-orange)](https://letsencrypt.org/)

---

## Why ubxcert?

Certbot runs the entire DNS-01 wildcard challenge flow inside a **single blocking process**. If that process dies between sending the token and Let's Encrypt validating DNS, the ACME session is gone — there is no resume path.

**ubxcert solves this with a two-step, fully resumable state machine:**

| Step | Command | What it does |
|---|---|---|
| 1 | `ubxcert request` | Creates the ACME order, computes DNS TXT values, **saves state to disk** |
| 2 | `ubxcert complete` | Polls DNS, notifies ACME, finalises, downloads certificate |

State is persisted at `/etc/ubxcert/` as plain JSON and PEM files. You can kill the process at any point and `ubxcert complete` will pick up exactly where it left off.

---

## Features

- **Zero external dependencies** — uses only PHP's built-in `openssl`, `curl`, and `json` extensions
- **Resumable sessions** — persistent JSON state survives process crashes and reboots
- **Wildcard + bare domain** in a single order (`*.example.com` + `example.com`)
- **Multi-server support** — OpenResty, Nginx, Apache (auto-detects running service)
- **Auto-renewal** via a single cron line — optional Cloudflare DNS automation
- **Let's Encrypt symlinks** at `/etc/letsencrypt/live/{domain}/` for full backward compatibility with existing tooling
- **Staging mode** for safe testing against Let's Encrypt's staging environment
- **JSON output** on every command for easy shell script integration
- **PHP 8.1+** — strict types throughout, no deprecated patterns

---

## Requirements

| Requirement | Version |
|---|---|
| PHP | ≥ 8.1 |
| ext-openssl | any |
| ext-curl | any |
| ext-json | any |
| dig | (for DNS polling in `complete`) |

---

## Installation

### Option A — Global install script (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/ubxty/ubxcert/main/install-ubxcert.sh | sudo bash
```

Or download and inspect first:

```bash
wget https://raw.githubusercontent.com/ubxty/ubxcert/main/install-ubxcert.sh
bash install-ubxcert.sh
```

The script:
- Checks and installs PHP + Composer if missing (Debian/Ubuntu/RHEL/AlmaLinux)
- Clones the package to `/opt/ubxcert/`
- Runs `composer install --no-dev`
- Symlinks `/usr/local/bin/ubxcert`
- Creates `/etc/ubxcert/` state directory
- Installs a daily auto-renewal cron at 03:15 UTC

### Option B — Manual

```bash
git clone git@github.com:ubxty/ubxcert.git /opt/ubxcert
cd /opt/ubxcert
composer install --no-dev --optimize-autoloader
ln -s /opt/ubxcert/bin/ubxcert /usr/local/bin/ubxcert
chmod +x /opt/ubxcert/bin/ubxcert
mkdir -p /etc/ubxcert
```

### Option C — From local source (for development)

```bash
bash install-ubxcert.sh --source /path/to/local/ubxcert
```

---

## Quick Start

```bash
# 1. Request the ACME order — outputs DNS TXT records to set
ubxcert request \
  --domains "*.example.com,example.com" \
  --email admin@example.com

# 2. Set the DNS TXT records shown in the output, then:
ubxcert complete --domain example.com --wait-dns 600

# 3. Inject the certificate into your web server and reload it
ubxcert install --domain example.com --webserver openresty
```

---

## Command Reference

### `ubxcert request`

Creates an ACME order and outputs the DNS-01 challenge records to set.

```
ubxcert request --domains "*.example.com,example.com" --email admin@example.com [OPTIONS]
```

| Option | Description |
|---|---|
| `--domains` | Comma-separated list of domains (wildcards supported) |
| `--email` | Contact email for the Let's Encrypt account |
| `--force` | Force a new order even if a pending one exists |
| `--staging` | Use Let's Encrypt staging environment |
| `--json` | Output JSON (ideal for shell script integration) |

**JSON output example:**

```json
{
  "domain": "example.com",
  "domains": ["*.example.com", "example.com"],
  "staging": false,
  "order_status": "pending",
  "challenges": [
    {
      "domain": "example.com",
      "challenge_host": "_acme-challenge.example.com",
      "txt_value": "ABC123...",
      "token": "raw-token",
      "status": "pending"
    }
  ],
  "next_step": "Set DNS TXT records above, then run: ubxcert complete --domain example.com"
}
```

---

### `ubxcert complete`

Resumes a saved order: polls DNS, triggers ACME challenges, finalises, downloads and saves the certificate.

```
ubxcert complete --domain example.com [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--domain` | — | Base domain (required) |
| `--wait-dns` | `0` | Seconds to wait for DNS propagation before polling (e.g. `600`) |
| `--staging` | false | Staging mode (auto-detected from saved state) |
| `--json` | false | JSON output |

Saves the certificate to:
```
/etc/ubxcert/certs/{domain}/
  fullchain.pem   — full chain for ssl_certificate
  cert.pem        — end-entity certificate only
  chain.pem       — intermediate chain
  privkey.pem     — private key

/etc/letsencrypt/live/{domain}/   ← symlinks (backward compat)
```

---

### `ubxcert install`

Injects certificate paths into a web server vhost and reloads the service.

```
ubxcert install --domain example.com --webserver openresty|nginx|apache [--conf /custom/path.conf]
```

| Webserver | Default vhost path |
|---|---|
| `openresty` | `/usr/local/openresty/nginx/conf/sites-available/{domain}.conf` |
| `nginx` | `/etc/nginx/sites-available/{domain}.conf` |
| `apache` | `/etc/apache2/sites-available/{domain}-le-ssl.conf` |

---

### `ubxcert renew`

Checks if a certificate is expiring within N days and renews it.

```
ubxcert renew --domain example.com [OPTIONS]
ubxcert renew --all [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--domain` | — | Renew a specific domain |
| `--all` | — | Renew all managed domains |
| `--days-before` | `30` | Renew if expiry is within this many days |
| `--cf-token` | — | Cloudflare API token (enables automatic DNS TXT record creation) |
| `--cf-zone-id` | — | Cloudflare Zone ID |
| `--webserver` | `nginx` | Web server to reload after renewal |

**Fully automated renewal with Cloudflare:**

```bash
ubxcert renew --all \
  --days-before 30 \
  --cf-token YOUR_CF_TOKEN \
  --cf-zone-id YOUR_ZONE_ID \
  --webserver openresty
```

The install script adds this cron automatically:
```
15 3 * * * root /usr/local/bin/ubxcert renew --all --days-before 30 >> /var/log/ubxcert/renew.log 2>&1
```

---

### `ubxcert list`

Lists all managed certificates with expiry and renewal status.

```
ubxcert list [--json]
```

```
DOMAIN                                  STATUS      EXPIRES                  RENEWAL NEEDED
------------------------------------------------------------------------------------------
example.com                             valid       2026-07-20 UTC (85d)     no
staging.example.com                     valid       2026-05-02 UTC (7d)      YES
```

---

### `ubxcert status`

Shows the full order state for a domain, including pending DNS challenge values.

```
ubxcert status --domain example.com [--json]
```

---

## State Directory Layout

```
/etc/ubxcert/
├── accounts/
│   └── admin-example-com/
│       ├── account.json     # Let's Encrypt account metadata + KID
│       └── private.pem      # RSA 4096 account key (chmod 600)
├── orders/
│   └── example.com/
│       ├── state.json       # Full order state — challenges, URLs, status
│       └── cert.key         # Certificate private key (chmod 600)
└── certs/
    └── example.com/
        ├── fullchain.pem
        ├── cert.pem
        ├── chain.pem
        └── privkey.pem
```

All files are written with `chmod 600` / directories with `chmod 700`.

---

## Shell Script Integration

Use `--json` to integrate ubxcert into any shell-based deployment workflow:

```bash
#!/bin/bash
CHALLENGE_JSON=$(ubxcert request \
  --domains "*.${DOMAIN},${DOMAIN}" \
  --email "${EMAIL}" \
  --force --json)

# Parse and act on each challenge
COUNT=$(echo "$CHALLENGE_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['challenges']))")

for i in $(seq 0 $((COUNT - 1))); do
  HOST=$(echo "$CHALLENGE_JSON"  | python3 -c "import sys,json; print(json.load(sys.stdin)['challenges'][$i]['challenge_host'])")
  VALUE=$(echo "$CHALLENGE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['challenges'][$i]['txt_value'])")
  # ... set DNS TXT $HOST = $VALUE via your DNS API ...
done

ubxcert complete --domain "${DOMAIN}" --wait-dns 600
ubxcert install  --domain "${DOMAIN}" --webserver nginx
```

---

## Staging / Testing

Always test against Let's Encrypt staging first:

```bash
ubxcert request --domains "*.example.com,example.com" --email test@example.com --staging
ubxcert complete --domain example.com --wait-dns 60 --staging
```

Staging certificates are not publicly trusted but are structurally identical to production ones, so your entire flow can be validated before hitting rate limits.

---

## Security Notes

- Account and certificate keys are **never** transmitted anywhere — only the public JWK is shared with Let's Encrypt.
- All private key files are written with `chmod 600`.
- The Cloudflare API token (for auto-renew) is passed as a CLI argument or environment variable and is never persisted to disk by ubxcert.
- CSR generation uses temporary files in `/tmp/` that are cleaned up in `finally` blocks.

---

## Architecture

```
src/
├── Application.php              CLI router — dispatches argv to commands
├── Acme/
│   ├── AcmeClient.php           Full ACME v2 HTTP protocol (RFC 8555)
│   └── JwsHelper.php            RSA key management, JWK, JWS signing (RFC 7515/7517)
├── Cert/
│   └── CertificateManager.php   Key gen, CSR with SANs, PEM chain split, symlinks
├── State/
│   └── StateManager.php         File-based JSON state persistence
└── Commands/
    ├── BaseCommand.php           Shared output, arg parsing, account resolution
    ├── RequestCommand.php        ubxcert request
    ├── CompleteCommand.php       ubxcert complete
    ├── InstallWebserverCommand.php  ubxcert install
    ├── RenewCommand.php          ubxcert renew
    ├── ListCommand.php           ubxcert list
    └── StatusCommand.php         ubxcert status
```

Key design decisions:
- **No external ACME libraries** — the full RFC 8555 protocol is implemented in `AcmeClient.php` using only `curl`
- **No framework dependency** — pure PHP 8.1+, runs anywhere
- **State-first design** — every command loads/saves JSON state so any step is independently resumable
- **Backward compat** — `/etc/letsencrypt/live/` symlinks mean existing nginx/apache configs that reference certbot paths keep working without any changes

---

## Contributing

Pull requests welcome. Please open an issue first for significant changes.

```bash
git clone git@github.com:ubxty/ubxcert.git
cd ubxcert
composer install
php bin/ubxcert --help
```

---

## License

MIT License — see [LICENSE](LICENSE).

---

## Credits

**ubxcert** is created and maintained by:

**Ravdeep Singh**
- Email: [info.ubxty@gmail.com](mailto:info.ubxty@gmail.com)
- LinkedIn: [linkedin.com/in/ravdeep-singh-a4544abb](https://www.linkedin.com/in/ravdeep-singh-a4544abb/)
- GitHub: [@ubxty](https://github.com/ubxty)

---

*ubxcert is an open-source project released under the MIT License. Contributions, issues and feature requests are welcome.*
