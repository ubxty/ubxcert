<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Ubxty\UbxCert\Util\VhostScanner;

/**
 * ubxcert doctor
 *
 * Checks the health of the ubxcert installation and SSL environment:
 *   • PHP version and required extensions
 *   • Binary location and version
 *   • State and log directories
 *   • Auto-renewal cron job
 *   • Web server status
 *   • Certificate health summary (expired / expiring soon)
 *
 * Usage:
 *   ubxcert doctor [--json]
 */
class DoctorCommand extends BaseCommand
{
    private const CRON_FILE = '/etc/cron.d/ubxcert-renew';
    private const BIN_PATH  = '/usr/local/bin/ubxcert';

    public function getName(): string        { return 'doctor'; }
    public function getDescription(): string { return 'Check ubxcert installation health and SSL environment'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $fix        = $this->hasFlag($args, 'fix');
        $errorCodes = $this->hasFlag($args, 'error-codes');

        if ($errorCodes) {
            return $this->printErrorCodes();
        }

        $checks = $this->runAllChecks();

        if ($fix) {
            $checks = $this->applyFixes($checks);
        }

        if ($this->jsonMode) {
            $this->outputJson($checks);
            return $checks['overall'] === 'healthy' ? 0 : 1;
        }

        $this->printReport($checks);
        return $checks['overall'] === 'critical' ? 1 : 0;
    }

    /**
     * Attempt to remediate the failing checks. Returns the updated
     * `$checks` array after the remediation pass. Currently:
     *   - Fails of `ext_*` (missing PHP extensions) trigger apt-get install.
     *   - Fails of `log_dir` or `dir_*` create the missing directories.
     *   - Permissions on /etc/ubxcert are normalized to 0700.
     *
     * The fix pass is intentionally conservative — it never modifies
     * anything it does not own. If a check fails and we don't know how
     * to fix it, the original failure is preserved.
     */
    private function applyFixes(array $checks): array
    {
        $fixed = [];
        foreach ($checks['checks'] as $c) {
            if ($c['passed']) {
                continue;
            }

            switch ($c['id']) {
                case 'dir_certbot_live':
                case 'log_dir':
                    if (isset($c['hint']) && str_contains($c['hint'], '/var/log')) {
                        @mkdir('/var/log/ubxcert', 0700, true);
                    }
                    $path = $this->inferPathFromLabel($c['label']);
                    if ($path !== null && !is_dir($path)) {
                        if (@mkdir($path, 0700, true) || is_dir($path)) {
                            $fixed[] = "Created directory: {$path}";
                            $c['passed'] = true;
                            $c['hint']   = 'directory created by --fix';
                            $c['level']  = 'ok';
                        }
                    }
                    break;

                case 'dir_certbot_live_archive':
                    // Deliberately skip — /etc/letsencrypt dirs are owned by certbot.
                    break;

                case str_starts_with($c['id'], 'ext_'):
                    $ext = substr($c['id'], 4);
                    if (PHP_OS_FAMILY === 'Linux' && $this->isRoot()) {
                        $ver = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
                        $pkg = "php{$ver}-{$ext}";
                        $out = [];
                        $code = 0;
                        @exec("apt-get install -y -qq {$pkg} 2>&1", $out, $code);
                        if ($code === 0 && extension_loaded($ext)) {
                            $fixed[] = "Installed PHP extension: {$ext}";
                            $c['passed'] = true;
                            $c['hint']   = 'installed by --fix';
                            $c['level']  = 'ok';
                        }
                    }
                    break;
            }
        }

        // Normalize /etc/ubxcert permissions if directory exists.
        if (is_dir('/etc/ubxcert')) {
            @chmod('/etc/ubxcert', 0700);
            $fixed[] = "Normalized permissions on /etc/ubxcert to 0700";
        }

        // Re-evaluate overall status after fix pass
        $criticals = array_filter($checks['checks'], fn($r) => $r['level'] === 'critical');
        $warnings  = array_filter($checks['checks'], fn($r) => $r['level'] === 'warn');
        $checks['overall'] = match (true) {
            !empty($criticals) => 'critical',
            !empty($warnings)  => 'warning',
            default            => 'healthy',
        };
        $checks['fixes_applied'] = $fixed;

        return $checks;
    }

    private function isRoot(): bool
    {
        return function_exists('posix_geteuid') ? posix_geteuid() === 0 : false;
    }

    private function inferPathFromLabel(string $label): ?string
    {
        if (preg_match('#(/[\w/.-]+)#', $label, $m)) {
            $path = $m[1];
            // Don't fix /etc/letsencrypt — owned by certbot.
            if (str_starts_with($path, '/etc/letsencrypt')) {
                return null;
            }
            return $path;
        }
        return null;
    }

    /**
     * Print the catalog of error_codes emitted by ubxcert commands. The
     * panel can `$(ubxcert doctor --error-codes --json)` to build a
     * mapping table for human-friendly error messages.
     */
    private function printErrorCodes(): int
    {
        $codes = [
            // RequestCommand
            'usage'                       => 'Invalid CLI usage (missing --domains or --email)',
            'invalid_challenge'           => '--challenge value is not dns or http',
            'http01_wildcard_unsupported' => 'HTTP-01 cannot serve wildcards; use --challenge dns',
            'incompatible_flags'          => 'Conflicting flags (e.g. --wait-http with --challenge dns)',
            'existing_order_mismatch'     => 'Saved order uses a different challenge type; pass --force to override',
            'account_setup_failed'        => 'Could not create or load the ACME account',
            'new_order_failed'            => 'ACME newOrder request failed',
            'authorization_fetch_failed'  => 'Failed to fetch an authorization object',
            'no_challenge_offered'        => 'ACME did not offer the requested challenge type for any domain',
            'cert_key_generation_failed'  => 'Could not generate the certificate private key',
            // RunAutoChain
            'complete_failed'             => 'Auto-chain `complete` step failed',
            'install_failed'              => 'Auto-chain `install` step failed',
            'no_webserver_detected'       => 'No active web server detected for install',
            // Request --renew
            'no_existing_cert'            => 'No cert to renew; run `ubxcert request` first',
            // Request --precheck
            'no_docroot'                  => 'No document root detected for the domain',
            'docroot_not_writable'        => 'Document root is not writable by the current user',
            'dns_resolution_failed'       => 'DNS resolution failed for the domain',
            'missing_php_extensions'      => 'Required PHP extensions are not loaded',
            'local_unreachable'           => 'Could not reach http://<domain>/ from local interface',
        ];

        if ($this->jsonMode) {
            $this->outputJson([
                'status'      => 'ok',
                'error_codes' => $codes,
                'count'       => count($codes),
            ]);
            return 0;
        }

        $this->out('');
        $this->out("\033[1m  ubxcert error codes\033[0m");
        $this->out('  ' . str_repeat('─', 60));
        foreach ($codes as $code => $desc) {
            $this->out("  \033[36m{$code}\033[0m");
            $this->out("    {$desc}");
        }
        $this->out('');
        return 0;
    }

    // -------------------------------------------------------------------------
    // Checks
    // -------------------------------------------------------------------------

    private function runAllChecks(): array
    {
        $results = [];

        // PHP version
        $phpVer     = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        $phpOk      = PHP_VERSION_ID >= 80100;
        $results[]  = $this->check(
            'php_version',
            "PHP version: {$phpVer}",
            $phpOk,
            $phpOk ? null : 'PHP 8.1 or higher required'
        );

        // PHP extensions
        foreach (['openssl', 'curl', 'json'] as $ext) {
            $has       = extension_loaded($ext);
            $results[] = $this->check(
                "ext_{$ext}",
                "PHP extension: {$ext}",
                $has,
                $has ? null : "Install php-{$ext}"
            );
        }

        // Binary
        $binExists = file_exists(self::BIN_PATH) && is_executable(self::BIN_PATH);
        $binTarget = $binExists && is_link(self::BIN_PATH) ? ' → ' . (readlink(self::BIN_PATH) ?: '?') : '';
        $results[] = $this->check(
            'binary',
            'Binary: ' . self::BIN_PATH . $binTarget,
            $binExists,
            $binExists ? null : 'Run install-ubxcert.sh to install'
        );

        // dig (used for DNS polling)
        exec('command -v dig 2>/dev/null', $out, $code);
        $hasDig    = $code === 0;
        $results[] = $this->check(
            'dig',
            'DNS tool: dig',
            $hasDig,
            $hasDig ? null : 'Install bind-utils or dnsutils for DNS polling'
        );

        // State directories
        foreach (['/etc/ubxcert', '/etc/ubxcert/certs', '/etc/ubxcert/orders', '/etc/ubxcert/accounts'] as $dir) {
            $exists    = is_dir($dir);
            $results[] = $this->check(
                'dir_' . basename($dir),
                "Directory: {$dir}",
                $exists,
                $exists ? null : "Run 'ubxcert install' or install-ubxcert.sh"
            );
        }

        // Log directory
        $logDir    = '/var/log/ubxcert';
        $logExists = is_dir($logDir);
        $results[] = $this->check(
            'log_dir',
            "Log directory: {$logDir}",
            $logExists,
            $logExists ? null : 'Will be created automatically on first run'
        );

        // Cron job
        $cronOk     = file_exists(self::CRON_FILE);
        $cronDetail = $cronOk ? ('  ' . trim(file_get_contents(self::CRON_FILE) ?: '')) : '';
        $results[]  = $this->check(
            'cron',
            'Auto-renewal cron: ' . self::CRON_FILE . ($cronOk ? '' : ' (NOT FOUND)'),
            $cronOk,
            $cronOk ? null : "Run install-ubxcert.sh or add: 15 3 * * * root /usr/local/bin/ubxcert renew --all --days-before 30 >> /var/log/ubxcert/renew.log 2>&1",
            'warn' // cron missing is a warning, not critical
        );

        // Web servers
        $wsStatus = VhostScanner::detectAll();
        foreach ($wsStatus as $ws => $status) {
            $running   = $status === 'running';
            $results[] = $this->check(
                "ws_{$ws}",
                "Web server: {$ws}",
                $running,
                null,
                $running ? 'ok' : 'info'  // stopped webservers are just info
            );
        }

        // Certificate health
        $certResults = $this->checkCerts();
        $results     = array_merge($results, $certResults);

        // Determine overall status
        $criticals = array_filter($results, fn($r) => $r['level'] === 'critical');
        $warnings  = array_filter($results, fn($r) => $r['level'] === 'warn');

        $overall = match (true) {
            !empty($criticals) => 'critical',
            !empty($warnings)  => 'warning',
            default            => 'healthy',
        };

        return [
            'overall'   => $overall,
            'checks'    => $results,
        ];
    }

    /** @return array<int, array<string, mixed>> */
    private function checkCerts(): array
    {
        $results = [];

        // ubxcert-managed certs
        $domains  = $this->state->listCertDomains();
        $expired  = 0;
        $expiring = 0;

        foreach ($domains as $domain) {
            $expiry = $this->certs->getCertExpiry($domain);
            if ($expiry === null) {
                continue;
            }
            $days = (int)(($expiry - time()) / 86400);
            if ($days < 0) {
                $expired++;
            } elseif ($days <= 30) {
                $expiring++;
            }
        }

        // certbot certs
        $leLive = '/etc/letsencrypt/live';
        if (is_dir($leLive)) {
            foreach (glob($leLive . '/*/cert.pem') ?: [] as $certPath) {
                if (basename(dirname($certPath)) === 'README') {
                    continue;
                }
                if (is_link($certPath) && str_starts_with((string) realpath($certPath), '/etc/ubxcert/')) {
                    continue;
                }
                $pem  = @file_get_contents($certPath);
                $cert = $pem ? @openssl_x509_read($pem) : false;
                if ($cert === false) {
                    continue;
                }
                $info = openssl_x509_parse($cert);
                $exp  = $info['validTo_time_t'] ?? null;
                if ($exp === null) {
                    continue;
                }
                $days = (int)(($exp - time()) / 86400);
                if ($days < 0) {
                    $expired++;
                } elseif ($days <= 30) {
                    $expiring++;
                }
            }
        }

        $total = count($domains);

        $results[] = $this->check(
            'certs_total',
            "Managed certificates: {$total}",
            true,
            null,
            'info'
        );

        if ($expired > 0) {
            $results[] = $this->check(
                'certs_expired',
                "{$expired} certificate(s) EXPIRED",
                false,
                "Run: ubxcert renew --all",
                'critical'
            );
        }

        if ($expiring > 0) {
            $results[] = $this->check(
                'certs_expiring',
                "{$expiring} certificate(s) expire within 30 days",
                false,
                "Run: ubxcert renew --all",
                'warn'
            );
        }

        if ($expired === 0 && $expiring === 0 && $total > 0) {
            $results[] = $this->check('certs_health', 'All certificates are healthy', true);
        }

        return $results;
    }

    private function check(
        string  $id,
        string  $label,
        bool    $passed,
        ?string $hint  = null,
        string  $failLevel = 'critical'
    ): array {
        return [
            'id'     => $id,
            'label'  => $label,
            'passed' => $passed,
            'hint'   => $hint,
            'level'  => $passed ? 'ok' : $failLevel,
        ];
    }

    // -------------------------------------------------------------------------
    // Output
    // -------------------------------------------------------------------------

    private function printReport(array $checks): void
    {
        echo "\n";
        echo "  \033[1mubxcert doctor\033[0m — System Health Report\n";
        echo '  ' . str_repeat('─', 60) . "\n\n";

        foreach ($checks['checks'] as $check) {
            $icon = match ($check['level']) {
                'ok'       => "\033[32m✓\033[0m",
                'warn'     => "\033[33m⚠\033[0m",
                'critical' => "\033[31m✗\033[0m",
                'info'     => "\033[36mℹ\033[0m",
                default    => ' ',
            };

            printf("  %s  %s\n", $icon, $check['label']);

            if ($check['hint'] !== null) {
                printf("       \033[2m→ %s\033[0m\n", $check['hint']);
            }
        }

        echo "\n  " . str_repeat('─', 60) . "\n";

        $overall = $checks['overall'];
        $badge   = match ($overall) {
            'healthy'  => "\033[42;30m HEALTHY  \033[0m",
            'warning'  => "\033[43;30m WARNINGS \033[0m",
            'critical' => "\033[41;37m CRITICAL \033[0m",
            default    => $overall,
        };

        echo "\n  Overall: {$badge}\n\n";

        if ($overall !== 'healthy') {
            echo "  Run \033[36mubxcert doctor --json\033[0m for machine-readable output.\n\n";
        }
    }
}
