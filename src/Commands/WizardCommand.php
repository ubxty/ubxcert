<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Ubxty\UbxCert\Util\VhostScanner;

/**
 * ubxcert wizard
 *
 * Interactive CLI wizard — auto-detects your web server, lists all configured
 * sites, lets you pick one, and walks you through issuing and installing a
 * Let's Encrypt certificate step by step.
 *
 * Usage:
 *   ubxcert wizard [--staging]
 */
class WizardCommand extends BaseCommand
{
    public function getName(): string        { return 'wizard'; }
    public function getDescription(): string { return 'Interactive certificate wizard — list sites, pick one, issue cert'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);
        $verbose = $this->hasFlag($args, 'v') || $this->hasFlag($args, 'verbose');

        $this->printBanner();

        // ── 1. Detect web server ────────────────────────────────────────────
        $wsStatus  = VhostScanner::detectAll();
        $primary   = VhostScanner::detectPrimary();

        echo "  Web server status:\n";
        foreach ($wsStatus as $ws => $status) {
            $dot = $status === 'running'
                ? "\033[32m● running\033[0m"
                : "\033[90m○ stopped\033[0m";
            printf("    %-12s %s\n", $ws, $dot);
        }

        if ($primary === null) {
            echo "\n  \033[31mNo supported web server detected.\033[0m\n";
            echo "  Install nginx, openresty, or apache2 and enable sites.\n\n";
            return 1;
        }

        echo "\n  \033[2mScanning vhost configurations...\033[0m\n";

        // ── 2. List all sites ───────────────────────────────────────────────
        $allSites = VhostScanner::listAllSites();

        // Deduplicate: prefer SSL entries; group by domain
        $byDomain = [];
        foreach ($allSites as $s) {
            $d = $s['domain'];
            if (!isset($byDomain[$d]) || (!$byDomain[$d]['ssl'] && $s['ssl'])) {
                $byDomain[$d] = $s;
            }
        }

        // Filter out wildcards, server defaults, and sites from non-primary webservers
        $sites = array_values(array_filter(
            $byDomain,
            fn($s) => $s['domain'] !== '_'
                && !str_starts_with($s['domain'], '*')
                && !str_starts_with($s['domain'], '.')
                && $s['webserver'] === $primary
        ));

        if (empty($sites)) {
            echo "\n  \033[33mNo virtual hosts found for \033[1m{$primary}\033[0m\033[33m in scanned directories.\033[0m\n\n";
            echo "  You can still issue a certificate manually:\n";
            echo '    ubxcert request --domains "*.example.com,example.com" --email admin@example.com' . "\n\n";
            return 0;
        }

        usort($sites, fn($a, $b) => strcmp($a['domain'], $b['domain']));

        // Check which domains already have an ubxcert/certbot cert
        $certDirs = ['/etc/ubxcert/certs', '/etc/letsencrypt/live'];
        $hasCert  = static function (string $domain) use ($certDirs): bool {
            $base = ltrim($domain, '*.');
            foreach ($certDirs as $dir) {
                if (is_dir("{$dir}/{$base}") || is_dir("{$dir}/*.{$base}")) {
                    return true;
                }
            }
            return false;
        };

        echo "\n";
        echo "  \033[1mVirtual hosts found (\033[36m{$primary}\033[0m\033[1m):\033[0m\n\n";

        if ($verbose) {
            printf("  \033[2m%-5s %-38s %-12s %-6s %-6s %s\033[0m\n", '#', 'DOMAIN', 'WEBSERVER', 'SSL', 'CERT', 'CONFIG PATH');
            echo '  ' . str_repeat('─', 100) . "\n";
        } else {
            printf("  \033[2m%-5s %-42s %-12s %-6s %-6s %s\033[0m\n", '#', 'DOMAIN', 'WEBSERVER', 'SSL', 'CERT', 'CONFIG');
            echo '  ' . str_repeat('─', 90) . "\n";
        }

        foreach ($sites as $i => $site) {
            $sslBadge  = $site['ssl'] ? "\033[32myes\033[0m" : "\033[33mno\033[0m ";
            $certified = $hasCert($site['domain']);
            $certBadge = $certified ? "\033[32m✓\033[0m    " : "\033[33m✗\033[0m    ";
            $configStr = $verbose
                ? ($site['config_path'] ?? $site['config'])
                : $site['config'];
            if ($verbose) {
                printf(
                    "  \033[36m%-5s\033[0m %-38s %-12s %-6s %-6s %s\n",
                    "[{$i}]",
                    $site['domain'],
                    $site['webserver'],
                    $sslBadge,
                    $certBadge,
                    $configStr
                );
            } else {
                printf(
                    "  \033[36m%-5s\033[0m %-42s %-12s %-6s %-6s %s\n",
                    "[{$i}]",
                    $site['domain'],
                    $site['webserver'],
                    $sslBadge,
                    $certBadge,
                    $configStr
                );
            }
        }

        echo "\n";

        // ── 3. Select domain ────────────────────────────────────────────────
        $selectedSite = null;
        while ($selectedSite === null) {
            echo '  Enter site number (or type a domain name, or "q" to quit): ';
            $input = trim((string) fgets(STDIN));

            if ($input === 'q' || $input === 'quit') {
                echo "\n  Wizard cancelled.\n\n";
                return 0;
            }

            if (is_numeric($input)) {
                $idx = (int) $input;
                if (isset($sites[$idx])) {
                    $selectedSite = $sites[$idx];
                } else {
                    echo "  \033[31mInvalid number.\033[0m\n";
                }
            } else {
                // Typed a domain name
                foreach ($sites as $s) {
                    if ($s['domain'] === $input) {
                        $selectedSite = $s;
                        break;
                    }
                }
                if ($selectedSite === null) {
                    // Allow custom domain not in list
                    echo "  Domain '{$input}' not found in vhosts. Use it anyway? [y/N]: ";
                    $confirm = strtolower(trim((string) fgets(STDIN)));
                    if ($confirm === 'y' || $confirm === 'yes') {
                        $selectedSite = ['domain' => $input, 'webserver' => $primary, 'ssl' => false, 'ssl_cert' => null, 'config' => ''];
                    }
                }
            }
        }

        $domain = $selectedSite['domain'];
        echo "\n  \033[1mSelected: {$domain}\033[0m\n\n";

        // ── 4. Ask for wildcard or bare domain ──────────────────────────────
        $baseDomain = ltrim($domain, '*.');
        echo "  Certificate type:\n";
        echo "    [1] Wildcard  *.{$baseDomain} + {$baseDomain}  (recommended)\n";
        echo "    [2] Single    {$domain} only\n\n";
        echo '  Choose [1/2]: ';
        $typeChoice = trim((string) fgets(STDIN));
        $useWildcard = $typeChoice !== '2';

        $domains = $useWildcard
            ? ["*.{$baseDomain}", $baseDomain]
            : [$domain];

        $domainsArg = implode(',', $domains);
        echo "\n  Domains: \033[36m{$domainsArg}\033[0m\n\n";

        // ── 5. Email ────────────────────────────────────────────────────────
        echo '  Let\'s Encrypt account email: ';
        $email = trim((string) fgets(STDIN));
        if ($email === '') {
            echo "  \033[31mEmail is required.\033[0m\n\n";
            return 1;
        }

        // ── 6. Staging? ─────────────────────────────────────────────────────
        if (!$this->staging) {
            echo "\n  Use Let's Encrypt \033[33mstaging\033[0m (fake cert, no rate limits)? [y/N]: ";
            $stg = strtolower(trim((string) fgets(STDIN)));
            if ($stg === 'y' || $stg === 'yes') {
                $this->staging = true;
            }
        }

        // ── 7. Run request ──────────────────────────────────────────────────
        echo "\n";
        $this->printStep(1, "Requesting ACME order from Let's Encrypt...");
        echo "\n";

        $reqArgs = ['--domains', $domainsArg, '--email', $email];
        if ($this->staging) {
            $reqArgs[] = '--staging';
        }

        $reqCmd = new RequestCommand();
        $rc     = $reqCmd->run($reqArgs);

        if ($rc !== 0) {
            echo "\n  \033[31mRequest step failed.\033[0m\n\n";
            return 1;
        }

        // ── 8. DNS prompt ───────────────────────────────────────────────────
        echo "\n";
        $this->printStep(2, 'Add the DNS TXT records shown above to your DNS provider.');
        echo "\n";
        echo "  \033[33m  For Cloudflare:\033[0m  DNS → Add record → Type=TXT, fill in Name and Content above\n";
        echo "  \033[33m  For cPanel/WHM:\033[0m  Zone Editor → Add TXT record\n";
        echo "\n";
        echo '  Press [Enter] when the TXT records are added (or wait a few minutes for propagation): ';
        fgets(STDIN);

        // ── 9. Run complete ─────────────────────────────────────────────────
        $this->printStep(3, 'Verifying DNS and finalising certificate...');
        echo "\n";

        $complArgs = ['--domain', $baseDomain, '--wait-dns', '600'];
        if ($this->staging) {
            $complArgs[] = '--staging';
        }

        $complCmd = new CompleteCommand();
        $rc2      = $complCmd->run($complArgs);

        if ($rc2 !== 0) {
            echo "\n  \033[31mCertificate issuance failed.\033[0m\n";
            echo "  Retry with:  ubxcert complete --domain {$baseDomain} --wait-dns 600\n\n";
            return 1;
        }

        // ── 10. Install into webserver ──────────────────────────────────────
        echo "\n";
        $this->printStep(4, 'Installing certificate into web server...');

        $webserver = $selectedSite['webserver'] ?? $primary;
        echo "\n  Web server: \033[36m{$webserver}\033[0m\n";
        echo '  Confirm install into ' . $webserver . '? [Y/n]: ';
        $conf = strtolower(trim((string) fgets(STDIN)));

        if ($conf !== 'n' && $conf !== 'no') {
            $instArgs = ['--domain', $baseDomain, '--webserver', $webserver];
            $instCmd  = new InstallWebserverCommand();
            $instCmd->run($instArgs);
        } else {
            echo "  Skipped. Run manually:\n";
            echo "    ubxcert install --domain {$baseDomain} --webserver {$webserver}\n";
        }

        // ── Done ────────────────────────────────────────────────────────────
        echo "\n";
        echo "  \033[42;30m DONE \033[0m  Certificate issued for \033[1m{$baseDomain}\033[0m\n\n";
        echo "  \033[2mManage your certs:\033[0m\n";
        echo "    ubxcert list\n";
        echo "    ubxcert renew --all\n";
        echo "    ubxcert doctor\n\n";

        return 0;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function printBanner(): void
    {
        echo "\n";
        echo "  \033[1;36m╔══════════════════════════════════════════════════╗\033[0m\n";
        echo "  \033[1;36m║\033[0m  \033[1mubxcert wizard\033[0m — Interactive Certificate Setup  \033[1;36m║\033[0m\n";
        echo "  \033[1;36m╚══════════════════════════════════════════════════╝\033[0m\n\n";
    }

    private function printStep(int $n, string $text): void
    {
        echo "  \033[1;36m[Step {$n}]\033[0m  {$text}\n";
    }
}
