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

        $checks = $this->runAllChecks();

        if ($this->jsonMode) {
            $this->outputJson($checks);
            return $checks['overall'] === 'healthy' ? 0 : 1;
        }

        $this->printReport($checks);
        return $checks['overall'] === 'critical' ? 1 : 0;
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
