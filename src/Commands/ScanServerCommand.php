<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

/**
 * ubxcert server
 *
 * Scans the server for all configured virtual hosts, auto-detects the active
 * web server (nginx / openresty / apache), checks SSL status per domain, and
 * cross-references with ubxcert-managed certificates.
 *
 * Usage:
 *   ubxcert server [--json] [--webserver nginx|openresty|apache] [--live-check]
 *
 * Options:
 *   --webserver   Force a specific web server instead of auto-detecting
 *   --live-check  Perform a live HTTPS connection test for SSL domains
 *   --json        Output results as JSON
 */
class ScanServerCommand extends BaseCommand
{
    /** Config directories to scan per web server type */
    private const CONF_DIRS = [
        'nginx' => [
            '/etc/nginx/sites-enabled',
            '/etc/nginx/conf.d',
        ],
        'openresty' => [
            '/usr/local/openresty/nginx/conf/sites-enabled',
            '/usr/local/openresty/nginx/conf/conf.d',
        ],
        'apache' => [
            '/etc/apache2/sites-enabled',
        ],
    ];

    public function getName(): string        { return 'server'; }
    public function getDescription(): string { return 'Scan server: list all virtual hosts, SSL status, and certificate health'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $webserverOpt = $this->extractOption($args, 'webserver');
        $liveCheck    = $this->hasFlag($args, 'live-check');

        // Detect running web servers
        $wsStatus = $this->detectWebservers();

        // Determine which to scan
        if ($webserverOpt !== null) {
            $active = [$webserverOpt];
        } else {
            $active = array_keys(array_filter($wsStatus, fn($s) => $s === 'running'));
        }

        // Fallback: nothing running — scan any webserver whose config dirs exist
        if (empty($active)) {
            foreach (array_keys(self::CONF_DIRS) as $ws) {
                foreach (self::CONF_DIRS[$ws] as $dir) {
                    if (is_dir($dir)) {
                        $active[] = $ws;
                        break;
                    }
                }
            }
            $active = array_unique($active);
        }

        // Collect all virtual hosts
        $allSites = [];
        foreach ($active as $ws) {
            $sites = $this->scanWebserver($ws, $liveCheck);
            foreach ($sites as &$site) {
                $site['webserver'] = $ws;
            }
            unset($site);
            $allSites = array_merge($allSites, $sites);
        }

        // Deduplicate by domain — prefer SSL-enabled entry
        $byDomain = [];
        foreach ($allSites as $site) {
            $d = $site['domain'];
            if (!isset($byDomain[$d]) || (!$byDomain[$d]['ssl'] && $site['ssl'])) {
                $byDomain[$d] = $site;
            }
        }

        $sites = array_values($byDomain);

        // Sort: SSL first, then alphabetically by domain
        usort($sites, function (array $a, array $b): int {
            if ($a['ssl'] !== $b['ssl']) {
                return (int) $b['ssl'] - (int) $a['ssl'];
            }
            return strcmp($a['domain'], $b['domain']);
        });

        $this->log('info', sprintf(
            'server scan: active=[%s] sites=%d',
            implode(',', $active),
            count($sites)
        ));

        if ($this->jsonMode) {
            $this->outputJson([
                'scan_time'  => gmdate('Y-m-d H:i:s') . ' UTC',
                'webservers' => $wsStatus,
                'scanned'    => $active,
                'sites'      => $sites,
                'summary'    => $this->buildSummary($sites),
            ]);
            return 0;
        }

        $this->printReport($wsStatus, $active, $sites);
        return 0;
    }

    // -------------------------------------------------------------------------
    // Web server detection
    // -------------------------------------------------------------------------

    /**
     * @return array<string, 'running'|'stopped'>
     */
    private function detectWebservers(): array
    {
        $serviceMap = ['nginx' => 'nginx', 'openresty' => 'openresty', 'apache' => 'apache2'];
        $result     = [];

        foreach ($serviceMap as $key => $service) {
            exec("systemctl is-active --quiet {$service} 2>/dev/null", $out, $code);
            $result[$key] = ($code === 0) ? 'running' : 'stopped';
        }

        return $result;
    }

    // -------------------------------------------------------------------------
    // Site scanning
    // -------------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    private function scanWebserver(string $ws, bool $liveCheck): array
    {
        $dirs  = self::CONF_DIRS[$ws] ?? [];
        $sites = [];

        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            foreach (glob($dir . '/*.conf') ?: [] as $file) {
                if (!is_readable($file)) {
                    continue;
                }
                $content = file_get_contents($file);
                if ($content === false) {
                    continue;
                }
                $parsed = ($ws === 'apache')
                    ? $this->parseApacheVhosts($content, $file)
                    : $this->parseNginxVhosts($content, $file);

                $sites = array_merge($sites, $parsed);
            }
        }

        // Enrich with ubxcert / cert expiry data
        foreach ($sites as &$site) {
            $this->enrichSite($site);
            if ($liveCheck && $site['ssl']) {
                $site['live_tls'] = $this->checkLiveTls($site['domain']) ? 'ok' : 'fail';
            }
        }
        unset($site);

        return $sites;
    }

    /**
     * Cross-reference a site with ubxcert state and cert files to populate
     * cert_source, expiry, and days_left fields.
     *
     * @param array<string, mixed> $site
     */
    private function enrichSite(array &$site): void
    {
        $domain = ltrim($site['domain'], '*.');

        $site['ubxcert']     = false;
        $site['cert_source'] = null;
        $site['expiry']      = null;
        $site['days_left']   = null;

        if ($this->state->certExists($domain)) {
            $expiry = $this->certs->getCertExpiry($domain);
            $site['ubxcert']     = true;
            $site['cert_source'] = 'ubxcert';
            if ($expiry !== null) {
                $site['expiry']    = gmdate('Y-m-d', $expiry) . ' UTC';
                $site['days_left'] = (int)(($expiry - time()) / 86400);
            }
            return;
        }

        // Try reading expiry from the cert file referenced in the vhost config
        if ($site['ssl'] && !empty($site['ssl_cert'])) {
            $pem  = @file_get_contents($site['ssl_cert']);
            $cert = $pem ? @openssl_x509_read($pem) : false;
            if ($cert !== false) {
                $info   = openssl_x509_parse($cert);
                $expiry = $info['validTo_time_t'] ?? null;
                if ($expiry !== null) {
                    $site['cert_source'] = 'external';
                    $site['expiry']      = gmdate('Y-m-d', $expiry) . ' UTC';
                    $site['days_left']   = (int)(($expiry - time()) / 86400);
                }
            }
        }
    }

    /** Perform a live TLS handshake check. Wildcards are skipped (returns false). */
    private function checkLiveTls(string $domain): bool
    {
        if (str_starts_with($domain, '*')) {
            return false;
        }
        $ch = curl_init("https://{$domain}/");
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $code > 0;
    }

    // -------------------------------------------------------------------------
    // Config parsing — nginx / openresty
    // -------------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    private function parseNginxVhosts(string $content, string $file): array
    {
        // Strip line comments before parsing
        $content = preg_replace('/#[^\n]*/', '', $content);

        // Match server { ... } blocks — handles one level of nested braces (location/if)
        preg_match_all('/\bserver\s*\{((?:[^{}]|\{[^{}]*\})*)\}/s', $content, $m);

        $sites = [];
        foreach ($m[1] as $block) {
            preg_match('/\bserver_name\s+([^;]+);/', $block, $snm);
            if (!$snm) {
                continue;
            }

            $names  = array_values(array_filter(preg_split('/\s+/', trim($snm[1]))));
            $hasSsl = (bool) preg_match('/\blisten\s+[^;]*\b443\b/i', $block)
                   || (bool) preg_match('/\bssl_certificate\s+/i', $block);

            preg_match('/\bssl_certificate\s+([^;]+);/', $block, $cm);
            $sslCert = $cm ? trim($cm[1]) : null;

            foreach ($names as $name) {
                if ($name === '_' || $name === '') {
                    continue;
                }
                $sites[] = [
                    'domain'   => $name,
                    'config'   => basename($file),
                    'ssl'      => $hasSsl,
                    'ssl_cert' => $sslCert,
                ];
            }
        }

        return $sites;
    }

    // -------------------------------------------------------------------------
    // Config parsing — Apache
    // -------------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    private function parseApacheVhosts(string $content, string $file): array
    {
        preg_match_all('/<VirtualHost[^>]*>(.*?)<\/VirtualHost>/si', $content, $m);

        $sites = [];
        foreach ($m[1] as $block) {
            preg_match('/^\s*ServerName\s+(\S+)/mi', $block, $snm);
            if (!$snm) {
                continue;
            }

            $hasSsl = (bool) preg_match('/\bSSLEngine\s+on\b/i', $block)
                   || (bool) preg_match('/\bSSLCertificateFile\b/i', $block);

            preg_match('/\bSSLCertificateFile\s+(\S+)/i', $block, $cm);
            $sslCert = $cm ? trim($cm[1]) : null;

            // Primary ServerName
            $sites[] = [
                'domain'   => trim($snm[1]),
                'config'   => basename($file),
                'ssl'      => $hasSsl,
                'ssl_cert' => $sslCert,
            ];

            // ServerAlias entries
            preg_match_all('/^\s*ServerAlias\s+(.+)/mi', $block, $am);
            foreach ($am[1] as $line) {
                foreach (array_filter(preg_split('/\s+/', trim($line))) as $alias) {
                    $sites[] = [
                        'domain'   => $alias,
                        'config'   => basename($file),
                        'ssl'      => $hasSsl,
                        'ssl_cert' => $sslCert,
                    ];
                }
            }
        }

        return $sites;
    }

    // -------------------------------------------------------------------------
    // Output
    // -------------------------------------------------------------------------

    /** @param array<int, array<string, mixed>> $sites */
    private function buildSummary(array $sites): array
    {
        $total    = count($sites);
        $ssl      = count(array_filter($sites, fn($s) => $s['ssl']));
        $ubxcert  = count(array_filter($sites, fn($s) => $s['ubxcert']));
        $external = count(array_filter($sites, fn($s) => $s['ssl'] && !$s['ubxcert']));
        $noSsl    = $total - $ssl;
        $exp30    = count(array_filter($sites, fn($s) => $s['days_left'] !== null && $s['days_left'] >= 0 && $s['days_left'] <= 30));
        $expired  = count(array_filter($sites, fn($s) => $s['days_left'] !== null && $s['days_left'] < 0));

        return compact('total', 'ssl', 'ubxcert', 'external', 'noSsl', 'exp30', 'expired');
    }

    /**
     * @param array<string, string> $wsStatus
     * @param string[]              $active
     * @param array<int, array<string, mixed>> $sites
     */
    private function printReport(array $wsStatus, array $active, array $sites): void
    {
        echo "\n\033[1m=== ubxcert Server Scan ===\033[0m\n";
        echo 'Scan time  : ' . gmdate('Y-m-d H:i:s') . " UTC\n\n";

        // Web server status
        echo "Web servers:\n";
        foreach ($wsStatus as $ws => $status) {
            $ind = ($status === 'running') ? "\033[32m● running\033[0m" : '○ stopped';
            printf("  %-12s %s\n", $ws, $ind);
        }
        echo "\n";

        if (empty($sites)) {
            echo "No virtual hosts found in scanned configuration directories.\n\n";
            echo "Scanned directories:\n";
            foreach ($active as $ws) {
                foreach (self::CONF_DIRS[$ws] ?? [] as $dir) {
                    echo "  {$dir}\n";
                }
            }
            return;
        }

        // Table header
        printf(
            "%-40s %-12s %-5s %-10s %-14s %s\n",
            'DOMAIN', 'WEBSERVER', 'SSL', 'SOURCE', 'EXPIRY', 'DAYS'
        );
        echo str_repeat('─', 96) . "\n";

        foreach ($sites as $site) {
            $ssl    = $site['ssl']         ? 'yes'     : 'no';
            $source = $site['cert_source'] ?? ($site['ssl'] ? 'unknown' : '-');
            $expiry = $site['expiry']      ?? '-';
            $days   = $site['days_left'];

            if ($days === null) {
                $daysStr = '-';
            } elseif ($days < 0) {
                $daysStr = "\033[31mEXPIRED\033[0m";
            } elseif ($days <= 14) {
                $daysStr = "\033[31m{$days}d\033[0m";
            } elseif ($days <= 30) {
                $daysStr = "\033[33m{$days}d\033[0m";
            } else {
                $daysStr = "{$days}d";
            }

            // $daysStr is last — ANSI codes don't need padding
            printf(
                "%-40s %-12s %-5s %-10s %-14s %s\n",
                $site['domain'],
                $site['webserver'],
                $ssl,
                $source,
                $expiry,
                $daysStr
            );
        }

        // Summary
        $s = $this->buildSummary($sites);
        echo "\n\033[1mSummary:\033[0m\n";
        echo "  Total sites      : {$s['total']}\n";
        echo "  SSL enabled      : {$s['ssl']}\n";
        echo "  ubxcert managed  : {$s['ubxcert']}\n";
        echo "  External SSL     : {$s['external']}\n";
        echo "  No SSL           : {$s['noSsl']}\n";

        if ($s['expired'] > 0) {
            echo "  \033[31mExpired          : {$s['expired']}\033[0m\n";
        }
        if ($s['exp30'] > 0) {
            echo "  \033[33mExpiring <30d    : {$s['exp30']}\033[0m\n";
        }
        echo "\n";
    }
}
