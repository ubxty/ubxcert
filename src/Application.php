<?php

declare(strict_types=1);

namespace Ubxty\UbxCert;

use Throwable;
use Ubxty\UbxCert\Commands\BaseCommand;
use Ubxty\UbxCert\Commands\CompleteCommand;
use Ubxty\UbxCert\Commands\DoctorCommand;
use Ubxty\UbxCert\Commands\InstallWebserverCommand;
use Ubxty\UbxCert\Commands\ListCommand;
use Ubxty\UbxCert\Commands\MigrateCommand;
use Ubxty\UbxCert\Commands\RenewCommand;
use Ubxty\UbxCert\Commands\RequestCommand;
use Ubxty\UbxCert\Commands\ScanServerCommand;
use Ubxty\UbxCert\Commands\StatusCommand;
use Ubxty\UbxCert\Commands\WizardCommand;

/**
 * ubxcert CLI application router.
 *
 * Dispatches argv to the appropriate command.
 */
class Application
{
    private const VERSION = '1.0.0';

    /** @var BaseCommand[] */
    private array $commands = [];

    public function __construct()
    {
        $this->register(new RequestCommand());
        $this->register(new CompleteCommand());
        $this->register(new InstallWebserverCommand());
        $this->register(new RenewCommand());
        $this->register(new ListCommand());
        $this->register(new StatusCommand());
        $this->register(new ScanServerCommand());
        $this->register(new DoctorCommand());
        $this->register(new WizardCommand());
        $this->register(new MigrateCommand());
    }

    private function register(BaseCommand $cmd): void
    {
        $this->commands[$cmd->getName()] = $cmd;
    }

    /**
     * @param string[] $argv
     */
    public function run(array $argv): int
    {
        $commandName = $argv[1] ?? null;
        $args        = array_slice($argv, 2);

        if ($commandName === null || in_array($commandName, ['--help', '-h'], true)) {
            $this->printHelp();
            return 0;
        }

        if (in_array($commandName, ['version', '--version', '-V'], true)) {
            echo "ubxcert " . self::VERSION . "\n";
            return 0;
        }

        // ubxcert help           → global help
        // ubxcert help <command> → per-command help
        if ($commandName === 'help') {
            $sub = $args[0] ?? null;
            if ($sub && isset($this->commands[$sub])) {
                $this->printCommandHelp($sub);
            } else {
                $this->printHelp();
            }
            return 0;
        }

        if (!isset($this->commands[$commandName])) {
            fwrite(STDERR, "ubxcert: unknown command '{$commandName}'\n\n");
            $this->printHelp();
            return 1;
        }

        // Per-command --help flag
        if (in_array('--help', $args, true) || in_array('-h', $args, true)) {
            $this->printCommandHelp($commandName);
            return 0;
        }

        try {
            return $this->commands[$commandName]->run($args);
        } catch (\Throwable $e) {
            fwrite(STDERR, "\033[31mubxcert error: " . $e->getMessage() . "\033[0m\n");
            if (in_array('--verbose', $args, true) || in_array('-v', $args, true)) {
                fwrite(STDERR, $e->getTraceAsString() . "\n");
            }
            return 1;
        }
    }

    private function printHelp(): void
    {
        $v = self::VERSION;
        echo <<<HELP

  \033[1;36m┌──────────────────────────────────────────────────────┐\033[0m
  \033[1;36m│\033[0m  \033[1mubxcert\033[0m v{$v}  —  ACME v2 SSL certificate manager   \033[1;36m│\033[0m
  \033[1;36m│\033[0m  Drop-in replacement for certbot. No dependencies.   \033[1;36m│\033[0m
  \033[1;36m└──────────────────────────────────────────────────────┘\033[0m

  \033[1mUsage:\033[0m  ubxcert <command> [options]
          ubxcert help <command>     per-command reference

  \033[1mCertificate lifecycle:\033[0m
    \033[36mrequest\033[0m    Create ACME order and print DNS-01 TXT challenge values
    \033[36mcomplete\033[0m   Verify DNS, finalize order, download + save certificate
    \033[36minstall\033[0m    Inject certificate into web server vhost and reload
    \033[36mrenew\033[0m      Renew one or all certificates expiring within N days

  \033[1mInspection:\033[0m
    \033[36mlist\033[0m       List ALL certificates — ubxcert + certbot (wildcard detection, webserver column)
    \033[36mstatus\033[0m     Show order/challenge state for a single domain
    \033[36mserver\033[0m     Scan all vhosts, auto-detect web server, show SSL health per domain

  \033[1mManagement:\033[0m
    \033[36mdoctor\033[0m     Check PHP, extensions, binary, dirs, cron, cert health — overall status
    \033[36mwizard\033[0m     Interactive TUI: detect webserver, pick site, issue + install cert
    \033[36mmigrate\033[0m    Migrate certbot-managed certs to ubxcert management

  \033[1mGlobal flags:\033[0m
    \033[33m--staging\033[0m   Use Let's Encrypt staging (safe for testing)
    \033[33m--json\033[0m      Machine-readable JSON output
    \033[33m--verbose\033[0m   Show detailed ACME protocol steps
    \033[33m--help\033[0m      Show per-command help (also: ubxcert help <cmd>)

  \033[1mTypical workflow:\033[0m

    \033[2m# 1. Request a wildcard cert — prints DNS TXT records to add\033[0m
    ubxcert request --domains "*.example.com,example.com" --email admin@example.com

    \033[2m# 2. Add the TXT records in your DNS, then complete the order\033[0m
    ubxcert complete --domain example.com --wait-dns 600

    \033[2m# 3. Install into your web server\033[0m
    ubxcert install  --domain example.com --webserver openresty

    \033[2m# 4. Check all certificates\033[0m
    ubxcert list

    \033[2m# 5. Renew automatically (also wired to cron)\033[0m
    ubxcert renew --all

  \033[2mDocs / source:  https://github.com/ubxty/ubxcert\033[0m

HELP;
    }

    private function printCommandHelp(string $name): void
    {
        $help = $this->commandHelpText();
        $text = $help[$name] ?? null;

        if ($text === null) {
            echo "No detailed help available for '{$name}'.\n";
            return;
        }

        echo "\n";
        foreach (explode("\n", $text) as $line) {
            echo "  {$line}\n";
        }
        echo "\n";
    }

    /** @return array<string, string> */
    private function commandHelpText(): array
    {
        return [
            'request' => <<<T
\033[1mubxcert request\033[0m — Create an ACME order and print DNS-01 TXT challenge values

\033[1mUsage:\033[0m
  ubxcert request --domains "*.example.com,example.com" --email admin@example.com
  ubxcert request --domains "site.com" --email admin@site.com --staging
  ubxcert request --domains "*.example.com,example.com" --email admin@example.com --force

\033[1mOptions:\033[0m
  --domains   \033[2mComma-separated list of domains (wildcard supported)\033[0m
  --email     \033[2mACME account email (used for Let's Encrypt notices)\033[0m
  --force     \033[2mDiscard any existing pending order and create a fresh one\033[0m
  --staging   \033[2mUse Let's Encrypt staging (no rate limits, fake cert)\033[0m
  --json      \033[2mOutput challenge data as JSON\033[0m

\033[1mWhat it does:\033[0m
  1. Registers (or re-uses) a Let's Encrypt account for --email
  2. Creates a new ACME order for all supplied domains
  3. Computes the DNS-01 TXT record values
  4. Prints them — you add these to your DNS

\033[1mNext step:\033[0m
  ubxcert complete --domain example.com --wait-dns 600
T,

            'complete' => <<<T
\033[1mubxcert complete\033[0m — Verify DNS, finalize order, download certificate

\033[1mUsage:\033[0m
  ubxcert complete --domain example.com
  ubxcert complete --domain example.com --wait-dns 600
  ubxcert complete --domain example.com --wait-dns 600 --staging

\033[1mOptions:\033[0m
  --domain     \033[2mBase domain (must match domain used in 'request')\033[0m
  --wait-dns   \033[2mSeconds to poll DNS for TXT propagation (default: 0 = no wait)\033[0m
  --staging    \033[2mMust match the flag used in 'request'\033[0m
  --json       \033[2mOutput certificate details as JSON\033[0m

\033[1mWhat it does:\033[0m
  1. Loads the order state saved by 'request'
  2. Optionally polls DNS until TXT records are visible
  3. Notifies ACME challenges are ready
  4. Polls until all authorisations are valid
  5. Submits a CSR, finalises the order
  6. Downloads the certificate chain
  7. Saves to /etc/ubxcert/certs/<domain>/
  8. Creates /etc/letsencrypt/live/<domain>/ symlinks for certbot compat

\033[1mFiles created:\033[0m
  /etc/ubxcert/certs/<domain>/fullchain.pem
  /etc/ubxcert/certs/<domain>/privkey.pem
  /etc/ubxcert/certs/<domain>/cert.pem
  /etc/ubxcert/certs/<domain>/chain.pem
T,

            'install' => <<<T
\033[1mubxcert install\033[0m — Inject certificate into a web server vhost and reload

\033[1mUsage:\033[0m
  ubxcert install --domain example.com --webserver openresty
  ubxcert install --domain example.com --webserver nginx
  ubxcert install --domain example.com --webserver apache
  ubxcert install --domain example.com --webserver nginx --conf /etc/nginx/sites-available/mysite.conf

\033[1mOptions:\033[0m
  --domain      \033[2mDomain whose certificate to install\033[0m
  --webserver   \033[2mTarget web server: openresty | nginx | apache\033[0m
  --conf        \033[2mOverride the vhost config file path (auto-detected by default)\033[0m

\033[1mDefault config paths:\033[0m
  openresty   /usr/local/openresty/nginx/conf/sites-available/<domain>.conf
  nginx       /etc/nginx/sites-available/<domain>.conf
  apache      /etc/apache2/sites-available/<domain>-le-ssl.conf
T,

            'renew' => <<<T
\033[1mubxcert renew\033[0m — Renew expiring certificates

\033[1mUsage:\033[0m
  ubxcert renew --domain example.com
  ubxcert renew --all
  ubxcert renew --all --days-before 45
  ubxcert renew --all --cf-token TOKEN --cf-zone-id ZONE_ID --webserver nginx

\033[1mOptions:\033[0m
  --domain       \033[2mRenew a single domain\033[0m
  --all          \033[2mRenew all managed domains expiring within --days-before\033[0m
  --days-before  \033[2mRenew if expiring within this many days (default: 30)\033[0m
  --cf-token     \033[2mCloudflare API token for automated DNS-01 (optional)\033[0m
  --cf-zone-id   \033[2mCloudflare Zone ID (required with --cf-token)\033[0m
  --webserver    \033[2mWebserver to reload after renewal (default: nginx)\033[0m

\033[1mNotes:\033[0m
  Without --cf-token the DNS step requires manual TXT record updates.
  The auto-renewal cron job is: /etc/cron.d/ubxcert-renew (runs 03:15 UTC daily).
T,

            'list' => <<<T
\033[1mubxcert list\033[0m — List ALL certificates on this server

\033[1mUsage:\033[0m
  ubxcert list
  ubxcert list --json
  ubxcert list --ubxcert-only
  ubxcert list --certbot-only

\033[1mOptions:\033[0m
  --ubxcert-only   \033[2mShow only ubxcert-managed certificates\033[0m
  --certbot-only   \033[2mShow only certbot-managed certificates\033[0m
  --json           \033[2mMachine-readable JSON output\033[0m

\033[1mSources scanned:\033[0m
  /etc/ubxcert/certs/       ubxcert-managed
  /etc/letsencrypt/live/    certbot-managed (symlinks into ubxcert are de-duplicated)

\033[1mOutput columns:\033[0m
  DOMAIN   SOURCE   STATUS   EXPIRES   DAYS
  Expiry is colour-coded: \033[32mgreen\033[0m = healthy, \033[33myellow\033[0m = <30d, \033[31mred\033[0m = <14d or expired
T,

            'status' => <<<T
\033[1mubxcert status\033[0m — Show order/challenge state for a single domain

\033[1mUsage:\033[0m
  ubxcert status --domain example.com
  ubxcert status --domain example.com --json

\033[1mOptions:\033[0m
  --domain   \033[2mDomain to inspect\033[0m
  --json     \033[2mMachine-readable JSON output\033[0m

\033[1mShows:\033[0m
  Order status, email, staging flag, created/completed timestamps,
  certificate expiry, and pending DNS challenge values (TXT records).
T,

            'server' => <<<T
\033[1mubxcert server\033[0m — Scan all vhosts, detect web server, show SSL health per domain

\033[1mUsage:\033[0m
  ubxcert server
  ubxcert server --json
  ubxcert server --webserver nginx
  ubxcert server --live-check

\033[1mOptions:\033[0m
  --webserver   \033[2mForce a specific server instead of auto-detecting (nginx|openresty|apache)\033[0m
  --live-check  \033[2mPerform a live HTTPS curl probe for each SSL domain\033[0m
  --json        \033[2mMachine-readable JSON output\033[0m

\033[1mWhat it does:\033[0m
  1. Auto-detects active web server via systemctl
  2. Scans sites-enabled/ and conf.d/ for vhost configs
  3. Parses server_name (nginx/openresty) or ServerName (apache)
  4. Cross-references domains with /etc/ubxcert/certs/ and external cert files
  6. Prints a summary: total / SSL / ubxcert / external / no-SSL / expiring / expired
T,

            'doctor' => <<<T
\033[1mubxcert doctor\033[0m — Check ubxcert installation health and SSL environment

\033[1mUsage:\033[0m
  ubxcert doctor
  ubxcert doctor --json

\033[1mChecks performed:\033[0m
  • PHP version (≥8.1)
  • PHP extensions: openssl, curl, json
  • Binary: /usr/local/bin/ubxcert
  • DNS tool: dig
  • State directories: /etc/ubxcert/{certs,orders,accounts}/
  • Log directory: /var/log/ubxcert/
  • Auto-renewal cron: /etc/cron.d/ubxcert-renew
  • Active web server detection
  • Certificate health: expired / expiring within 30 days

\033[1mExit codes:\033[0m
  0 = healthy or warnings only
  1 = critical issues found
T,

            'wizard' => <<<T
\033[1mubxcert wizard\033[0m — Interactive certificate setup wizard

\033[1mUsage:\033[0m
  ubxcert wizard
  ubxcert wizard --staging

\033[1mOptions:\033[0m
  --staging   \033[2mUse Let's Encrypt staging throughout (safe for testing)\033[0m

\033[1mInteractive steps:\033[0m
  1. Detect and list active web servers
  2. Show all vhosts (with SSL status)
  3. Pick a site by number or type a domain
  4. Choose wildcard *.domain.com + domain.com or single domain
  5. Enter account email
  6. Run 'ubxcert request' and print DNS TXT challenge values
  7. Pause — add TXT records to DNS — press Enter to continue
  8. Run 'ubxcert complete --wait-dns 600'
  9. Optionally run 'ubxcert install' for the detected web server
T,

            'migrate' => <<<T
\033[1mubxcert migrate\033[0m — Migrate certbot certificates to ubxcert management

\033[1mUsage:\033[0m
  ubxcert migrate --all
  ubxcert migrate --domain example.com
  ubxcert migrate --all --dry-run
  ubxcert migrate --all --email admin@example.com

\033[1mOptions:\033[0m
  --all        \033[2mMigrate all certbot certs in /etc/letsencrypt/live/\033[0m
  --domain     \033[2mMigrate a single domain\033[0m
  --email      \033[2mEmail to record in state.json for future renewals (default: migrated@ubxcert.local)\033[0m
  --dry-run    \033[2mPrint what would happen without writing any files\033[0m

\033[1mWhat it does per domain:\033[0m
  1. Copies PEM files from /etc/letsencrypt/live/<domain>/ → /etc/ubxcert/certs/<domain>/
  2. Creates a minimal state.json so 'ubxcert renew --all' can manage the cert
  3. Updates /etc/letsencrypt/live/<domain>/ symlinks to point at the copied files
  4. Originals are preserved in certbot's archive directory

\033[1mNotes:\033[0m
  Domains already in /etc/ubxcert/certs/ are skipped.
  After migration, set the correct email with your next renewal request.
T,
        ];
    }
}

