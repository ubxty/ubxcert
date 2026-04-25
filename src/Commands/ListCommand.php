<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Ubxty\UbxCert\Util\VhostScanner;

/**
 * ubxcert list
 *
 * Lists ALL certificates on the server — ubxcert-managed and certbot-managed.
 * Acts as a drop-in replacement for `certbot certificates`.
 *
 * Sources scanned:
 *   /etc/ubxcert/certs/       — certs managed by this tool
 *   /etc/letsencrypt/live/    — certbot-managed certs (symlinks into ubxcert
 *                               are skipped to avoid double-counting)
 *
 * Usage:
 *   ubxcert list [--json] [--ubxcert-only] [--certbot-only]
 */
class ListCommand extends BaseCommand
{
    private const LE_LIVE = '/etc/letsencrypt/live';

    public function getName(): string        { return 'list'; }
    public function getDescription(): string { return 'List ALL certificates on this server (ubxcert + certbot)'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $ubxcertOnly = $this->hasFlag($args, 'ubxcert-only');
        $certbotOnly = $this->hasFlag($args, 'certbot-only');

        $rows = $this->discoverAll($ubxcertOnly, $certbotOnly);

        // Sort: ubxcert first, then certbot; within each group alphabetically
        usort($rows, static function (array $a, array $b): int {
            if ($a['source'] !== $b['source']) {
                return strcmp($a['source'], $b['source']); // certbot < ubxcert alphabetically — swap
            }
            return strcmp($a['domain'], $b['domain']);
        });
        // Put ubxcert before certbot
        usort($rows, static function (array $a, array $b): int {
            $order = ['ubxcert' => 0, 'certbot' => 1, 'unknown' => 2];
            $oa = $order[$a['source']] ?? 3;
            $ob = $order[$b['source']] ?? 3;
            return $oa !== $ob ? $oa - $ob : strcmp($a['domain'], $b['domain']);
        });

        if ($this->jsonMode) {
            $this->outputJson([
                'total'  => count($rows),
                'certs'  => $rows,
            ]);
            return 0;
        }

        if (empty($rows)) {
            $this->out('No certificates found.');
            $this->out('');
            $this->out('Locations scanned:');
            $this->out('  /etc/ubxcert/certs/      (ubxcert)');
            $this->out('  /etc/letsencrypt/live/   (certbot)');
            return 0;
        }

        $this->printTable($rows);
        return 0;
    }

    // -------------------------------------------------------------------------
    // Discovery
    // -------------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    private function discoverAll(bool $ubxcertOnly, bool $certbotOnly): array
    {
        $rows = [];
        $seen = [];   // domain => true, to avoid double-counting

        // --- 1. ubxcert-managed certs (/etc/ubxcert/certs/) -----------------
        if (!$certbotOnly) {
            foreach ($this->state->listCertDomains() as $domain) {
                $expiry   = $this->certs->getCertExpiry($domain);
                $renewal  = $this->certs->needsRenewal($domain);
                $order    = $this->state->loadOrderState($domain);
                $daysLeft = $expiry !== null ? (int)(($expiry - time()) / 86400) : null;
                $certDir  = $this->state->getCertDir($domain);

                $certPath    = $certDir . '/cert.pem';
                [, , $wildcard] = $this->readCertInfo($certPath);
                $installedOn = VhostScanner::domainSslWebserver($domain);

                $rows[]        = $this->buildRow($domain, 'ubxcert', $certDir, $expiry, $daysLeft, $renewal, $order['order_status'] ?? 'valid', [], $wildcard, $installedOn);
                $seen[$domain] = true;
            }
        }

        // --- 2. Let's Encrypt live dir (certbot or other ACME tools) --------
        if (!$ubxcertOnly && is_dir(self::LE_LIVE)) {
            foreach (glob(self::LE_LIVE . '/*/cert.pem') ?: [] as $certPath) {
                $domain = basename(dirname($certPath));

                // Skip the README placeholder certbot creates
                if ($domain === 'README') {
                    continue;
                }

                // Skip symlinks that point into /etc/ubxcert/ — already counted
                if (is_link($certPath)) {
                    $target = realpath($certPath);
                    if ($target !== false && str_starts_with($target, '/etc/ubxcert/')) {
                        $seen[$domain] = true;
                        continue;
                    }
                }

                // Skip domains already discovered via ubxcert state
                if (isset($seen[$domain])) {
                    continue;
                }

                [$expiry, $sans] = $this->readCertInfo($certPath);
                $daysLeft = $expiry !== null ? (int)(($expiry - time()) / 86400) : null;
                $renewal  = $daysLeft !== null && $daysLeft < 30;
                $certDir  = dirname($certPath);

                $isWildcard  = $this->isWildcardCert($sans);
                $installedOn = VhostScanner::domainSslWebserver($domain);

                $rows[]        = $this->buildRow($domain, 'certbot', $certDir, $expiry, $daysLeft, $renewal, 'valid', $sans, $isWildcard, $installedOn);
                $seen[$domain] = true;
            }
        }

        return $rows;
    }

    /** @return array{0: int|null, 1: string[], 2: bool} */
    private function readCertInfo(string $certPath): array
    {
        $pem = @file_get_contents($certPath);
        if ($pem === false) {
            return [null, [], false];
        }

        $cert = @openssl_x509_read($pem);
        if ($cert === false) {
            return [null, [], false];
        }

        $info   = openssl_x509_parse($cert);
        $expiry = $info['validTo_time_t'] ?? null;

        // Extract SANs from extensions
        $sans = [];
        $ext  = $info['extensions']['subjectAltName'] ?? '';
        foreach (explode(',', $ext) as $part) {
            $part = trim($part);
            if (str_starts_with($part, 'DNS:')) {
                $sans[] = ltrim($part, 'DNS:');
            }
        }

        return [$expiry, $sans, $this->isWildcardCert($sans)];
    }

    /** @param string[] $sans */
    private function isWildcardCert(array $sans): bool
    {
        foreach ($sans as $san) {
            if (str_starts_with($san, '*.')) {
                return true;
            }
        }
        return false;
    }

    /** @param string[] $sans */
    private function buildRow(
        string  $domain,
        string  $source,
        string  $certDir,
        ?int    $expiry,
        ?int    $daysLeft,
        bool    $renewal,
        string  $status,
        array   $sans        = [],
        bool    $wildcard    = false,
        ?string $installedOn = null
    ): array {
        return [
            'domain'        => $domain,
            'source'        => $source,
            'status'        => $status,
            'expiry'        => $expiry !== null ? gmdate('Y-m-d', $expiry) . ' UTC' : 'N/A',
            'days_left'     => $daysLeft,
            'needs_renewal' => $renewal,
            'cert_dir'      => $certDir,
            'sans'          => $sans,
            'wildcard'      => $wildcard,
            'installed_on'  => $installedOn,
        ];
    }

    // -------------------------------------------------------------------------
    // Output
    // -------------------------------------------------------------------------

    /** @param array<int, array<string, mixed>> $rows */
    private function printTable(array $rows): void
    {
        $total   = count($rows);
        $expired = count(array_filter($rows, fn($r) => $r['days_left'] !== null && $r['days_left'] < 0));
        $renew   = count(array_filter($rows, fn($r) => $r['needs_renewal']));
        $ubx     = count(array_filter($rows, fn($r) => $r['source'] === 'ubxcert'));
        $cb      = count(array_filter($rows, fn($r) => $r['source'] === 'certbot'));

        echo "\n";
        echo "\033[1m  Certificates on this server\033[0m";
        echo "  ({$total} total";
        if ($ubx)  { echo ", \033[36m{$ubx} ubxcert\033[0m"; }
        if ($cb)   { echo ", \033[33m{$cb} certbot\033[0m"; }
        if ($renew){ echo ", \033[31m{$renew} need renewal\033[0m"; }
        echo ")\n\n";

        // Table header
        printf(
            "  \033[2m%-42s %-3s %-10s %-8s %-12s %-14s %s\033[0m\n",
            'DOMAIN', 'WC', 'SOURCE', 'SERVER', 'STATUS', 'EXPIRES', 'DAYS'
        );
        echo '  ' . str_repeat('─', 104) . "\n";

        $lastSource = null;
        foreach ($rows as $row) {
            // Visual separator between source groups
            if ($row['source'] !== $lastSource && $lastSource !== null) {
                echo "\n";
            }
            $lastSource = $row['source'];

            $srcColor = match ($row['source']) {
                'ubxcert' => "\033[36m",   // cyan
                'certbot' => "\033[33m",   // yellow
                default   => "\033[90m",   // grey
            };

            $daysLeft = $row['days_left'];
            if ($daysLeft === null) {
                $daysStr = '-';
            } elseif ($daysLeft < 0) {
                $daysStr = "\033[31mEXPIRED\033[0m";
            } elseif ($daysLeft <= 14) {
                $daysStr = "\033[31m{$daysLeft}d\033[0m";
            } elseif ($daysLeft <= 30) {
                $daysStr = "\033[33m{$daysLeft}d\033[0m";
            } else {
                $daysStr = "\033[32m{$daysLeft}d\033[0m";
            }

            $statusColor = $row['status'] === 'valid' ? "\033[32m" : "\033[33m";
            $wcFlag      = $row['wildcard']     ? "\033[35m★\033[0m" : ' ';
            $installed   = $row['installed_on'] ?? '-';

            printf(
                "  %-42s  %-1s  {$srcColor}%-10s\033[0m %-8s {$statusColor}%-12s\033[0m %-14s %s\n",
                $row['domain'],
                $wcFlag,
                $row['source'],
                $installed,
                $row['status'],
                $row['expiry'],
                $daysStr
            );

            // Show SANs as subdued continuation lines when they differ from domain
            if (!empty($row['sans'])) {
                $extraSans = array_filter($row['sans'], fn($s) => $s !== $row['domain']);
                if (!empty($extraSans)) {
                    foreach ($extraSans as $san) {
                        $wcMark = str_starts_with($san, '*.') ? "\033[35m★\033[0m " : '  ';
                        printf("  \033[2m  ↳ %s%-39s\033[0m\n", $wcMark, $san);
                    }
                }
            }
        }

        echo '  ' . str_repeat('─', 104) . "\n";

        if ($expired > 0 || $renew > 0) {
            echo "\n";
            if ($expired > 0) {
                echo "  \033[31m✗ {$expired} certificate(s) EXPIRED. Renew immediately:\033[0m\n";
                echo "    ubxcert renew --all\n";
            } elseif ($renew > 0) {
                echo "  \033[33m⚠  {$renew} certificate(s) expire within 30 days.\033[0m\n";
                echo "    ubxcert renew --all\n";
            }
        } else {
            echo "\n  \033[32m✓ All certificates are healthy.\033[0m\n";
        }

        echo "\n  \033[2mCert dirs:  /etc/ubxcert/certs/  |  /etc/letsencrypt/live/\033[0m\n\n";
    }
}
