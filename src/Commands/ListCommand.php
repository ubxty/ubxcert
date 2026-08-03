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
        $domain      = $this->extractOption($args, 'domain');
        $daysBefore  = $this->extractOption($args, 'days-before');
        $filterExp   = $this->hasFlag($args, 'filter=expiring');
        $filterExpSoon = $this->hasFlag($args, 'filter=expiring-soon');
        $filterExpOpt  = $this->extractOption($args, 'filter');
        $installedOnly = $this->hasFlag($args, 'filter=installed');
        $uninstalledOnly = $this->hasFlag($args, 'filter=uninstalled');

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

        // --- Apply filters (--domain, --days-before, --filter=...) ----------
        $rows = $this->applyFilters($rows, $domain, $daysBefore, $filterExp, $filterExpSoon, $filterExpOpt, $installedOnly, $uninstalledOnly);

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
                $certInfo    = $this->readCertInfo($certPath);
                $sans        = $certInfo['sans'];
                $wildcard    = $certInfo['wildcard'];
                $installedOn = VhostScanner::domainSslWebserver($domain);
                $vhost       = VhostScanner::domainSslWebserverDetails($domain);

                $rows[]        = $this->buildRow(
                    $domain,
                    'ubxcert',
                    $certDir,
                    $expiry,
                    $daysLeft,
                    $renewal,
                    $order['order_status'] ?? 'valid',
                    $sans,
                    $wildcard,
                    $installedOn,
                    $certInfo,
                    $vhost
                );
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

                $certInfo    = $this->readCertInfo($certPath);
                $expiry      = $certInfo['expiry'];
                $sans        = $certInfo['sans'];
                $daysLeft    = $expiry !== null ? (int)(($expiry - time()) / 86400) : null;
                $renewal     = $daysLeft !== null && $daysLeft < 30;
                $certDir     = dirname($certPath);

                $isWildcard  = $this->isWildcardCert($sans);
                $installedOn = VhostScanner::domainSslWebserver($domain);
                $vhost       = VhostScanner::domainSslWebserverDetails($domain);

                $rows[]        = $this->buildRow(
                    $domain,
                    'certbot',
                    $certDir,
                    $expiry,
                    $daysLeft,
                    $renewal,
                    'valid',
                    $sans,
                    $isWildcard,
                    $installedOn,
                    $certInfo,
                    $vhost
                );
                $seen[$domain] = true;
            }
        }

        return $rows;
    }

    /**
     * Read every X.509 field the panel needs to surface to the operator.
     *
     * Returns an associative array so adding fields doesn't break tuple
     * destructuring at call sites. Legacy positional shape (expiry, sans,
     * wildcard) is preserved as the first three keys.
     *
     * @return array{
     *   expiry: ?int,
     *   valid_from: ?int,
     *   sans: string[],
     *   wildcard: bool,
     *   issuer: ?string,
     *   subject: ?string,
     *   serial: ?string,
     *   signature_algorithm: ?string,
     *   key_algorithm: ?string,
     *   key_size: ?int,
     *   fingerprint_sha256: ?string,
     * }
     */
    private function readCertInfo(string $certPath): array
    {
        $empty = [
            'expiry'               => null,
            'valid_from'           => null,
            'sans'                 => [],
            'wildcard'             => false,
            'issuer'               => null,
            'subject'              => null,
            'serial'               => null,
            'signature_algorithm'  => null,
            'key_algorithm'        => null,
            'key_size'             => null,
            'fingerprint_sha256'   => null,
        ];

        $pem = @file_get_contents($certPath);
        if ($pem === false) {
            return $empty;
        }

        $cert = @openssl_x509_read($pem);
        if ($cert === false) {
            return $empty;
        }

        $info      = openssl_x509_parse($cert);
        $expiry    = $info['validTo_time_t']   ?? null;
        $validFrom = $info['validFrom_time_t'] ?? null;

        // Extract SANs from extensions.subjectAltName — comma-separated `DNS:` labels.
        $sans = [];
        $ext  = $info['extensions']['subjectAltName'] ?? '';
        foreach (explode(',', $ext) as $part) {
            $part = trim($part);
            if (str_starts_with($part, 'DNS:')) {
                $sans[] = ltrim($part, 'DNS:');
            }
        }

        // Subject & issuer — openssl_x509_parse returns name arrays.
        // Render to RFC 4514 string form so the panel can show "CN=…, O=…".
        $issuer  = $this->renderX509Name($info['issuer']  ?? []);
        $subject = $this->renderX509Name($info['subject'] ?? []);

        // Serial number — openssl_x509_parse returns it as a hex string.
        $serial = isset($info['serialNumber']) ? strtoupper((string) $info['serialNumber']) : null;

        // Signature algorithm — prefer Short Name (e.g. `sha256WithRSAEncryption`),
        // fall back to Long Name.
        $signatureAlgorithm = $info['signatureTypeSN']
            ?? ($info['signatureTypeLN'] ?? null);

        // Public key — type + size. openssl_x509_parse does NOT return these
        // directly; pull them out of the parsed public-key resource.
        $keyAlgorithm = null;
        $keySize      = null;
        $pkey = @openssl_pkey_get_public($cert);
        if ($pkey !== false) {
            $details = openssl_pkey_get_details($pkey);
            if (is_array($details)) {
                $typeMap = [
                    OPENSSL_KEYTYPE_RSA => 'RSA',
                    OPENSSL_KEYTYPE_DSA => 'DSA',
                    OPENSSL_KEYTYPE_DH  => 'DH',
                    OPENSSL_KEYTYPE_EC  => 'EC',
                ];
                $keyAlgorithm = $typeMap[$details['type'] ?? -1] ?? null;
                $keySize      = isset($details['bits']) ? (int) $details['bits'] : null;
            }
        }

        // SHA-256 fingerprint — decode the PEM body to DER and hash it.
        // Avoids depending on the openssl binary being on PATH.
        $fingerprint = $this->sha256FingerprintFromPem($pem);

        return [
            'expiry'              => $expiry,
            'valid_from'          => $validFrom,
            'sans'                => $sans,
            'wildcard'            => $this->isWildcardCert($sans),
            'issuer'              => $issuer,
            'subject'             => $subject,
            'serial'              => $serial,
            'signature_algorithm' => $signatureAlgorithm,
            'key_algorithm'       => $keyAlgorithm,
            'key_size'            => $keySize,
            'fingerprint_sha256'  => $fingerprint,
        ];
    }

    /**
     * Render an X.509 name array (issuer/subject from openssl_x509_parse)
     * as an RFC 4514–style string for the panel.
     *
     * @param array<string, string> $name
     */
    private function renderX509Name(array $name): ?string
    {
        if ($name === []) {
            return null;
        }
        $parts = [];
        // Order RDNs from most-specific to least: CN, then O, OU, L, ST, C.
        foreach (['CN', 'O', 'OU', 'L', 'ST', 'C', 'E'] as $rdn) {
            if (isset($name[$rdn]) && $name[$rdn] !== '') {
                $parts[] = $rdn . '=' . $name[$rdn];
            }
        }
        return $parts === [] ? null : implode(', ', $parts);
    }

    /**
     * Compute the SHA-256 fingerprint of a PEM-encoded X.509 certificate
     * (uppercase hex, colon-separated, matching `openssl x509 -fingerprint -sha256`).
     * Returns null if the body cannot be decoded.
     */
    private function sha256FingerprintFromPem(string $pem): ?string
    {
        $body = '';
        $inBody = false;
        foreach (preg_split('/\r?\n/', $pem) ?: [] as $line) {
            $line = rtrim($line);
            if (str_starts_with($line, '-----BEGIN')) {
                $inBody = true;
                continue;
            }
            if (str_starts_with($line, '-----END')) {
                break;
            }
            if ($inBody && $line !== '') {
                $body .= $line;
            }
        }
        $der = base64_decode($body, true);
        if ($der === false || $der === '') {
            return null;
        }
        $hex = hash('sha256', $der);
        // Format as `AA:BB:CC:…` so it matches the openssl CLI fingerprint form.
        $pairs = str_split($hex, 2);
        return strtoupper(implode(':', $pairs));
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

    /**
     * @param array{
     *   expiry: ?int,
     *   valid_from: ?int,
     *   sans: string[],
     *   wildcard: bool,
     *   issuer: ?string,
     *   subject: ?string,
     *   serial: ?string,
     *   signature_algorithm: ?string,
     *   key_algorithm: ?string,
     *   key_size: ?int,
     *   fingerprint_sha256: ?string,
     * } $certInfo
     * @param string[] $sans
     */
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
        ?string $installedOn = null,
        array   $certInfo    = [],
        ?array  $vhost       = null
    ): array {
        $validFromIso = isset($certInfo['valid_from'])
            ? gmdate('Y-m-d\TH:i:s\Z', (int) $certInfo['valid_from'])
            : null;
        $validToIso = $expiry !== null ? gmdate('Y-m-d\TH:i:s\Z', $expiry) : null;

        return [
            'domain'               => $domain,
            'source'               => $source,
            'status'               => $status,
            'expiry'               => $expiry !== null ? gmdate('Y-m-d', $expiry) . ' UTC' : 'N/A',
            'days_left'            => $daysLeft,
            'needs_renewal'        => $renewal,
            'cert_dir'             => $certDir,
            'sans'                 => $sans,
            'wildcard'             => $wildcard,
            'installed_on'         => $installedOn,
            'issuer'               => $certInfo['issuer']               ?? null,
            'subject'              => $certInfo['subject']              ?? null,
            'serial'               => $certInfo['serial']               ?? null,
            'signature_algorithm'  => $certInfo['signature_algorithm']  ?? null,
            'key_algorithm'        => $certInfo['key_algorithm']        ?? null,
            'key_size'             => $certInfo['key_size']             ?? null,
            'fingerprint_sha256'   => $certInfo['fingerprint_sha256']   ?? null,
            'valid_from'           => $validFromIso,
            'valid_to'             => $validToIso,
            'vhost'                => $vhost,
        ];
    }

    // -------------------------------------------------------------------------
    // Filtering
    // -------------------------------------------------------------------------

    /**
     * Apply the --domain, --days-before, and --filter=... reductions to the
     * discovered set. Filters are AND'd. Returns the filtered rows.
     *
     * @param array<int, array<string, mixed>> $rows
     * @return array<int, array<string, mixed>>
     */
    private function applyFilters(
        array $rows,
        ?string $domain,
        ?string $daysBefore,
        bool $filterExp,
        bool $filterExpSoon,
        ?string $filterOpt,
        bool $installedOnly,
        bool $uninstalledOnly
    ): array {
        if ($domain !== null) {
            $rows = array_values(array_filter($rows, fn($r) => strcasecmp($r['domain'], $domain) === 0));
        }

        if ($filterExpSoon) {
            $rows = array_values(array_filter($rows, fn($r) => $r['days_left'] !== null && $r['days_left'] <= 14));
        } elseif ($filterExp) {
            $rows = array_values(array_filter($rows, fn($r) => $r['needs_renewal']));
        } elseif ($daysBefore !== null) {
            $threshold = max(0, (int) $daysBefore);
            $rows = array_values(array_filter($rows, fn($r) => $r['days_left'] !== null && $r['days_left'] <= $threshold));
        } elseif ($filterOpt !== null) {
            // Generic --filter=foo resolver
            $rows = array_values(array_filter($rows, function ($r) use ($filterOpt) {
                return match (strtolower($filterOpt)) {
                    'expiring'      => $r['needs_renewal'],
                    'expiring-soon' => $r['days_left'] !== null && $r['days_left'] <= 14,
                    'expired'       => $r['days_left'] !== null && $r['days_left'] < 0,
                    'installed'     => !empty($r['installed_on']),
                    'uninstalled'   => empty($r['installed_on']),
                    'wildcard'      => $r['wildcard'] ?? false,
                    default         => true,
                };
            }));
        }

        if ($installedOnly) {
            $rows = array_values(array_filter($rows, fn($r) => !empty($r['installed_on'])));
        }
        if ($uninstalledOnly) {
            $rows = array_values(array_filter($rows, fn($r) => empty($r['installed_on'])));
        }

        return $rows;
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
