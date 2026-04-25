<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Util;

/**
 * Shared web-server vhost scanner.
 *
 * Detects running web servers (nginx / openresty / apache) and parses their
 * enabled vhost configuration files to build a list of virtual hosts.
 *
 * Used by ScanServerCommand, ListCommand, WizardCommand, and DoctorCommand.
 */
class VhostScanner
{
    /** Config directories indexed by web-server key */
    public const CONF_DIRS = [
        'openresty' => [
            '/usr/local/openresty/nginx/conf/sites-enabled',
            '/usr/local/openresty/nginx/conf/sites-available',
            '/usr/local/openresty/nginx/conf/conf.d',
        ],
        'nginx' => [
            '/etc/nginx/sites-enabled',
            '/etc/nginx/sites-available',
            '/etc/nginx/conf.d',
        ],
        'apache' => [
            '/etc/apache2/sites-enabled',
            '/etc/apache2/sites-available',
        ],
    ];

    /** Systemd service names per web-server key */
    private const SERVICES = [
        'openresty' => 'openresty',
        'nginx'     => 'nginx',
        'apache'    => 'apache2',
    ];

    // -------------------------------------------------------------------------
    // Web server detection
    // -------------------------------------------------------------------------

    /**
     * Return status of every supported web server.
     *
     * @return array<string, 'running'|'stopped'>
     */
    public static function detectAll(): array
    {
        $result = [];
        foreach (self::SERVICES as $key => $service) {
            exec("systemctl is-active --quiet {$service} 2>/dev/null", $out, $code);
            $result[$key] = ($code === 0) ? 'running' : 'stopped';
        }
        return $result;
    }

    /**
     * Return the first running web server key, or null if none.
     */
    public static function detectPrimary(): ?string
    {
        foreach (self::SERVICES as $key => $service) {
            exec("systemctl is-active --quiet {$service} 2>/dev/null", $out, $code);
            if ($code === 0) {
                return $key;
            }
        }
        // Fallback: check if any config dir exists
        foreach (self::CONF_DIRS as $key => $dirs) {
            foreach ($dirs as $dir) {
                if (is_dir($dir)) {
                    return $key;
                }
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Site listing
    // -------------------------------------------------------------------------

    /**
     * List all virtual-host entries across all web servers (or a specific one).
     *
     * Each entry: ['domain', 'webserver', 'ssl', 'ssl_cert', 'config']
     *
     * @return array<int, array<string, mixed>>
     */
    public static function listAllSites(?string $webserverFilter = null): array
    {
        $servers = $webserverFilter !== null
            ? [$webserverFilter => self::CONF_DIRS[$webserverFilter] ?? []]
            : self::CONF_DIRS;

        $all  = [];
        $seen = []; // deduplicate domain+ssl pairs

        foreach ($servers as $ws => $dirs) {
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
                    $entries = ($ws === 'apache')
                        ? self::parseApache($content, $file)
                        : self::parseNginx($content, $file);

                    foreach ($entries as $entry) {
                        $key = $entry['domain'] . '|' . ($entry['ssl'] ? '1' : '0') . '|' . $ws;
                        if (!isset($seen[$key])) {
                            $entry['webserver'] = $ws;
                            $all[]              = $entry;
                            $seen[$key]         = true;
                        }
                    }
                }
            }
        }

        return $all;
    }

    /**
     * Check whether a given domain has SSL enabled in any vhost config.
     * Returns the webserver key if found, null otherwise.
     */
    public static function domainSslWebserver(string $domain): ?string
    {
        foreach (self::listAllSites() as $site) {
            if (
                ($site['domain'] === $domain || $site['domain'] === '*.' . ltrim($domain, '*.'))
                && $site['ssl']
            ) {
                return $site['webserver'];
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Config parsers
    // -------------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    private static function parseNginx(string $content, string $file): array
    {
        // Strip line comments first
        $content = preg_replace('/#[^\n]*/', '', $content) ?? $content;

        // Use a brace-counter to extract top-level server{} blocks.
        // The old regex (?:[^{}]|\{[^{}]*\})* only handles 2 levels of nesting
        // and silently drops configs with 3+ levels (e.g. location { lua_block { } }).
        $blocks = self::extractServerBlocks($content);

        $sites = [];
        foreach ($blocks as $block) {
            preg_match('/\bserver_name\s+([^;]+);/', $block, $snm);
            if (!$snm) {
                continue;
            }
            $names  = array_values(array_filter(preg_split('/\s+/', trim($snm[1]))));
            $hasSsl = (bool) preg_match('/\blisten\s+[^;]*\b443\b/i', $block)
                   || (bool) preg_match('/\bssl_certificate\s+/i', $block);

            preg_match('/\bssl_certificate\s+([^;]+);/', $block, $cm);
            $sslCert = isset($cm[1]) ? trim($cm[1]) : null;

            foreach ($names as $name) {
                if ($name === '_' || $name === '') {
                    continue;
                }
                // Nginx uses .example.com (leading dot) as shorthand for
                // both example.com and *.example.com. Normalise it to the bare domain.
                if (str_starts_with($name, '.')) {
                    $name = ltrim($name, '.');
                }
                if ($name === '') {
                    continue;
                }
                $sites[] = [
                    'domain'      => $name,
                    'config'      => basename($file),
                    'config_path' => $file,
                    'ssl'         => $hasSsl,
                    'ssl_cert'    => $sslCert,
                ];
            }
        }

        return $sites;
    }

    /**
     * Extract the contents of all top-level server{} blocks using brace counting.
     * Handles arbitrary nesting depth (lua_block, map, geo, etc.).
     *
     * @return list<string>
     */
    private static function extractServerBlocks(string $content): array
    {
        $blocks = [];
        $offset = 0;
        $len    = strlen($content);

        while ($offset < $len) {
            // Find next 'server' keyword immediately followed by optional whitespace then '{'
            if (!preg_match('/\bserver\s*\{/s', $content, $m, PREG_OFFSET_CAPTURE, $offset)) {
                break;
            }

            $start = $m[0][1] + strlen($m[0][0]); // position right after '{'
            $depth = 1;
            $pos   = $start;

            while ($pos < $len && $depth > 0) {
                $ch = $content[$pos];
                if ($ch === '{') {
                    $depth++;
                } elseif ($ch === '}') {
                    $depth--;
                }
                $pos++;
            }

            if ($depth === 0) {
                $blocks[] = substr($content, $start, $pos - $start - 1);
            }

            $offset = $pos;
        }

        return $blocks;
    }

    /** @return array<int, array<string, mixed>> */
    private static function parseApache(string $content, string $file): array
    {
        preg_match_all('/<VirtualHost[^>]*>(.*?)<\/VirtualHost>/si', $content, $m);

        $sites = [];
        foreach ($m[1] ?? [] as $block) {
            preg_match('/^\s*ServerName\s+(\S+)/mi', $block, $snm);
            if (!$snm) {
                continue;
            }
            $hasSsl  = (bool) preg_match('/\bSSLEngine\s+on\b/i', $block)
                    || (bool) preg_match('/\bSSLCertificateFile\b/i', $block);

            preg_match('/\bSSLCertificateFile\s+(\S+)/i', $block, $cm);
            $sslCert = isset($cm[1]) ? trim($cm[1]) : null;

            $sites[] = [
                'domain'      => trim($snm[1]),
                'config'      => basename($file),
                'config_path' => $file,
                'ssl'      => $hasSsl,
                'ssl_cert' => $sslCert,
            ];

            preg_match_all('/^\s*ServerAlias\s+(.+)/mi', $block, $am);
            foreach ($am[1] ?? [] as $line) {
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
}
