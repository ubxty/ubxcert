<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Util;

/**
 * Shared web-server vhost scanner.
 *
 * Detects running web servers and parses their enabled vhost
 * configuration files to build a list of virtual hosts. The parser
 * also extracts the document root per site so the HTTP-01 auto-webroot
 * flow (WebrootChallenger) knows where to write the challenge file.
 *
 * Used by ScanServerCommand, ListCommand, WizardCommand, DoctorCommand,
 * and WebrootChallenger (via resolveDocroot).
 */
class VhostScanner
{
    /**
     * Config directories indexed by web-server key.
     *
     * Multiple paths per webserver because distros lay out the vhost
     * tree differently (sites-available, conf.d, custom build dirs,
     * etc.). The first path that exists wins per scan.
     */
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
            '/etc/httpd/conf.d',
        ],
        'caddy' => [
            '/etc/caddy/sites-enabled',
            '/etc/caddy/conf.d',
            '/etc/caddy',
        ],
        'litespeed' => [
            '/usr/local/lsws/conf/vhosts',
            '/usr/local/lsws/conf',
            '/etc/httpd/conf.d',
            '/etc/apache2/sites-enabled',
        ],
        'lighttpd' => [
            '/etc/lighttpd/conf-enabled',
            '/etc/lighttpd/conf-available',
        ],
        'nginx-unit' => [
            '/etc/nginx-unit',
            '/usr/libexec/nginx-unit',
        ],
    ];

    /**
     * Config file globs per web-server key (some servers do not
     * use the .conf extension — lighttpd uses no extension or
     * .lua, nginx-unit stores JSON).
     *
     * @var array<string, list<string>>
     */
    private const CONF_GLOBS = [
        'openresty'  => ['*.conf'],
        'nginx'      => ['*.conf'],
        'apache'     => ['*.conf'],
        'caddy'      => ['Caddyfile', '*.conf', '*.caddy'],
        'litespeed'  => ['*.conf', 'vhconf.conf'],
        'lighttpd'   => ['*.conf', '*.lua'],
        'nginx-unit' => ['*.json'],
    ];

    /** Systemd service names per web-server key */
    private const SERVICES = [
        'openresty'  => 'openresty',
        'nginx'      => 'nginx',
        'apache'     => 'apache2',
        'caddy'      => 'caddy',
        'litespeed'  => 'lshttpd',
        'lighttpd'   => 'lighttpd',
        'nginx-unit' => 'unitd',
    ];

    /** Alt systemd names tried in addition to the canonical one. */
    private const SERVICE_ALIASES = [
        'apache'     => ['apache2', 'httpd'],
        'litespeed'  => ['lshttpd', 'litespeed'],
        'nginx-unit' => ['unitd', 'nginx-unit'],
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
            $result[$key] = self::isServiceRunning($key, $service) ? 'running' : 'stopped';
        }
        return $result;
    }

    /**
     * Return the first running web server key, or null if none.
     *
     * Order matters — the first running service is the one whose
     * docroot will be used for auto-webroot. nginx and openresty win
     * over apache/caddy when multiple are running, which matches
     * what humans typically expect on a UB Panel box.
     */
    public static function detectPrimary(): ?string
    {
        foreach (self::SERVICES as $key => $service) {
            if (self::isServiceRunning($key, $service)) {
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

    private static function isServiceRunning(string $key, string $primary): bool
    {
        $names = [$primary];
        foreach (self::SERVICE_ALIASES[$key] ?? [] as $alias) {
            if (!in_array($alias, $names, true)) {
                $names[] = $alias;
            }
        }
        foreach ($names as $name) {
            // Escape the name — it comes from a const table, never user input.
            $escaped = escapeshellarg($name);
            exec("systemctl is-active --quiet {$escaped} 2>/dev/null", $out, $code);
            if ($code === 0) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Site listing
    // -------------------------------------------------------------------------

    /**
     * List all virtual-host entries across all web servers (or a specific one).
     *
     * Each entry: ['domain', 'webserver', 'ssl', 'ssl_cert', 'docroot', 'config', 'config_path']
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
            $entries = self::scanWebserver($ws, $dirs);
            foreach ($entries as $entry) {
                $key = $entry['domain'] . '|' . ($entry['ssl'] ? '1' : '0') . '|' . $ws;
                if (!isset($seen[$key])) {
                    $entry['webserver'] = $ws;
                    $all[]              = $entry;
                    $seen[$key]         = true;
                }
            }
        }

        return $all;
    }

    /**
     * @param array<string, list<string>> $dirs
     * @return array<int, array<string, mixed>>
     */
    private static function scanWebserver(string $ws, array $dirs): array
    {
        $entries  = [];
        $globs    = self::CONF_GLOBS[$ws] ?? ['*.conf'];
        $fileList = self::collectFiles($dirs, $globs);

        foreach ($fileList as $file) {
            if (!is_readable($file)) {
                continue;
            }
            $content = file_get_contents($file);
            if ($content === false) {
                continue;
            }
            $parsed = self::dispatchParse($ws, $content, $file);

            // Fallback: if the parser found nothing in the file, derive the
            // domain from the filename itself (e.g. example.com.conf → example.com).
            // This ensures sites are never missed due to parser limitations.
            if (empty($parsed)) {
                $name = pathinfo($file, PATHINFO_FILENAME);
                if ($name !== 'default' && $name !== '' && !str_starts_with($name, '.')) {
                    $parsed = [[
                        'domain'      => $name,
                        'config'      => basename($file),
                        'config_path' => $file,
                        'ssl'         => false,
                        'ssl_cert'    => null,
                        'docroot'     => null,
                    ]];
                }
            }

            foreach ($parsed as $entry) {
                // Fill in the path even when the parser omitted it
                $entry['config_path'] = $entry['config_path'] ?? $file;
                $entry['config']      = $entry['config']      ?? basename($file);
                $entry['docroot']     = $entry['docroot']     ?? null;
                $entries[]            = $entry;
            }
        }

        return $entries;
    }

    /**
     * @param list<string> $dirs
     * @param list<string> $globs
     * @return list<string>
     */
    private static function collectFiles(array $dirs, array $globs): array
    {
        $files = [];
        $seen  = [];
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            foreach ($globs as $glob) {
                foreach (glob(rtrim($dir, '/') . '/' . $glob) ?: [] as $file) {
                    if (isset($seen[$file])) {
                        continue;
                    }
                    $seen[$file] = true;
                    $files[]     = $file;
                }
            }
        }
        return $files;
    }

    /**
     * Dispatch to the parser for a given webserver key.
     *
     * @return array<int, array<string, mixed>>
     */
    private static function dispatchParse(string $ws, string $content, string $file): array
    {
        return match ($ws) {
            'apache'     => self::parseApache($content, $file),
            'caddy'      => self::parseCaddy($content, $file),
            'litespeed'  => self::parseLitespeed($content, $file),
            'lighttpd'   => self::parseLighttpd($content, $file),
            'nginx-unit' => self::parseNginxUnit($content, $file),
            default      => self::parseNginx($content, $file),
        };
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
    // Docroot resolution (used by WebrootChallenger)
    // -------------------------------------------------------------------------

    /**
     * Resolve the document root for a single domain, scanning every
     * supported webserver's enabled configs in priority order
     * (nginx → openresty → apache → caddy → litespeed → lighttpd →
     * nginx-unit). First match wins.
     *
     * @return array{docroot:string,webserver:string,config:string,config_path:string}|null
     */
    public static function resolveDocroot(string $domain): ?array
    {
        $domain = strtolower(trim($domain));
        if ($domain === '') {
            return null;
        }

        foreach (self::listAllSites() as $site) {
            if (strtolower($site['domain']) !== $domain) {
                continue;
            }
            if (!empty($site['docroot']) && is_string($site['docroot'])) {
                return [
                    'docroot'     => $site['docroot'],
                    'webserver'   => $site['webserver'],
                    'config'      => $site['config']      ?? null,
                    'config_path' => $site['config_path'] ?? null,
                ];
            }
        }

        // No vhost config provided a docroot — fall back to common
        // cPanel/UB Panel defaults so auto-webroot still has somewhere
        // to write. Order: per-domain home, then a generic vhosts root.
        $homeRoot = '/home/' . $domain . '/public';
        if (is_dir($homeRoot)) {
            return [
                'docroot'     => $homeRoot,
                'webserver'   => self::detectPrimary() ?? 'unknown',
                'config'      => null,
                'config_path' => null,
            ];
        }

        $wwwRoot = '/var/www/' . $domain . '/public_html';
        if (is_dir($wwwRoot)) {
            return [
                'docroot'     => $wwwRoot,
                'webserver'   => self::detectPrimary() ?? 'unknown',
                'config'      => null,
                'config_path' => null,
            ];
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

            // `root /var/www/...;` — may be unquoted, single- or double-quoted.
            // Take the LAST occurrence in the block so that location-level
            // overrides win over the server-level default.
            $docroot = null;
            if (preg_match_all('/\broot\s+("[^"]+"|\x27[^\x27]+\x27|\S+)\s*;/i', $block, $rm)) {
                $last = end($rm[1]);
                $docroot = trim((string) $last, "\"' \t");
            }

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
                    'docroot'     => $docroot,
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

            // DocumentRoot may be quoted or unquoted
            $docroot = null;
            if (preg_match('/^\s*DocumentRoot\s+("[^"]+"|\x27[^\x27]+\x27|\S+)/mi', $block, $drm)) {
                $docroot = trim((string) $drm[1], "\"' \t");
            }

            $sites[] = [
                'domain'      => trim($snm[1]),
                'config'      => basename($file),
                'config_path' => $file,
                'ssl'         => $hasSsl,
                'ssl_cert'    => $sslCert,
                'docroot'     => $docroot,
            ];

            preg_match_all('/^\s*ServerAlias\s+(.+)/mi', $block, $am);
            foreach ($am[1] ?? [] as $line) {
                foreach (array_filter(preg_split('/\s+/', trim($line))) as $alias) {
                    $sites[] = [
                        'domain'      => $alias,
                        'config'      => basename($file),
                        'config_path' => $file,
                        'ssl'         => $hasSsl,
                        'ssl_cert'    => $sslCert,
                        'docroot'     => $docroot,
                    ];
                }
            }
        }

        return $sites;
    }

    /**
     * Parse a Caddyfile (or a Caddyfile snippet). Caddy vhost syntax:
     *
     *   example.com {
     *       root * /var/www/example.com
     *       tls internal
     *   }
     *
     * Domain is the first label on a site block, root is the
     * `root *` / `root` directive inside it.
     *
     * @return array<int, array<string, mixed>>
     */
    private static function parseCaddy(string $content, string $file): array
    {
        $sites = [];

        // Strip # comments and // comments
        $stripped = preg_replace('/#[^\n]*/', '', $content) ?? $content;

        // Walk the file collecting { … } blocks at indent level 0.
        // A site block starts with a non-whitespace label followed by { … }.
        $lines   = explode("\n", $stripped);
        $n       = count($lines);
        $i       = 0;
        while ($i < $n) {
            $line = trim($lines[$i]);
            if ($line === '' || str_starts_with($line, '#')) {
                $i++;
                continue;
            }
            // Look for "<domain> {"
            if (preg_match('/^([A-Za-z0-9._*-]+)\s*\{\s*$/', $line, $m)) {
                $domain = $m[1];
                $block  = '';
                $depth  = 1;
                $i++;
                while ($i < $n && $depth > 0) {
                    $cur = $lines[$i];
                    $block .= $cur . "\n";
                    $depth += substr_count($cur, '{') - substr_count($cur, '}');
                    $i++;
                }
                $hasSsl = (bool) preg_match('/\btls\s+/i', $block);
                preg_match('/\broot\s+\*?\s+("[^"]+"|\x27[^\x27]+\x27|\S+)/i', $block, $rm);
                $docroot = isset($rm[1]) ? trim($rm[1], "\"' \t") : null;

                // Split label into individual hostnames if comma/space-separated.
                foreach (preg_split('/[\s,]+/', $domain) ?: [] as $name) {
                    $name = trim($name);
                    if ($name === '' || $name === '*' || str_starts_with($name, '#')) {
                        continue;
                    }
                    $sites[] = [
                        'domain'      => $name,
                        'config'      => basename($file),
                        'config_path' => $file,
                        'ssl'         => $hasSsl,
                        'ssl_cert'    => null,
                        'docroot'     => $docroot,
                    ];
                }
                continue;
            }
            // Standalone host: line — record domain-less, skip.
            $i++;
        }

        return $sites;
    }

    /**
     * Parse a LiteSpeed / OpenLiteSpeed vhost config.
     *
     * LiteSpeed config files are Apache-compatible plus a `vhconfig`
     * block. Two layouts to handle:
     *
     *   1. Pure Apache conf (DocumentRoot, ServerName, VirtualHost) →
     *      handled by parseApache-style extraction.
     *   2. Native LSWS conf with `virtualhost <vh> { … docRoot $VH_ROOT/... }`
     *      where $VH_ROOT expands to /usr/local/lsws/<vh>.
     *
     * @return array<int, array<string, mixed>>
     */
    private static function parseLitespeed(string $content, string $file): array
    {
        $sites = [];

        // Layout 1 — Apache-style. Re-use the apache extractor.
        $apacheHits = self::parseApache($content, $file);
        foreach ($apacheHits as $h) {
            $sites[] = $h;
        }

        // Layout 2 — Native LSWS `virtualhost <vhName> { … }`.
        if (preg_match_all('/\bvirtualhost\s+(\S+)\s*\{/i', $content, $vm, PREG_SET_ORDER)) {
            foreach ($vm as $match) {
                $vhName = $match[1];
                $start  = strpos($content, $match[0]) + strlen($match[0]);
                $depth  = 1;
                $pos    = $start;
                $len    = strlen($content);
                while ($pos < $len && $depth > 0) {
                    $ch = $content[$pos];
                    if ($ch === '{') {
                        $depth++;
                    } elseif ($ch === '}') {
                        $depth--;
                    }
                    $pos++;
                }
                if ($depth !== 0) {
                    continue;
                }
                $block = substr($content, $start, $pos - $start - 1);

                preg_match('/\bvhDomain\s+(\S+)/i', $block, $dm);
                $domain = isset($dm[1]) ? $dm[1] : $vhName . '.localhost';

                preg_match('/\bdocRoot\s+("[^"]+"|\x27[^\x27]+\x27|\S+)/i', $block, $drm);
                $rawRoot = isset($drm[1]) ? trim($drm[1], "\"' \t") : null;
                // Expand $VH_ROOT placeholder
                if ($rawRoot !== null && str_contains($rawRoot, '$VH_ROOT')) {
                    $rawRoot = str_replace('$VH_ROOT', '/usr/local/lsws/' . $vhName, $rawRoot);
                }

                $hasSsl = (bool) preg_match('/\bSSL\s+on\b/i', $block);

                $sites[] = [
                    'domain'      => $domain,
                    'config'      => basename($file),
                    'config_path' => $file,
                    'ssl'         => $hasSsl,
                    'ssl_cert'    => null,
                    'docroot'     => $rawRoot,
                ];
            }
        }

        return $sites;
    }

    /**
     * Parse a lighttpd config file. lighttpd uses Lua-syntax config
     * (no `<VirtualHost>` blocks). The conventional pattern is:
     *
     *   $HTTP["host"] == "example.com" {
     *       server.document-root = "/var/www/example.com"
     *   }
     *
     * Plain $SERVER["socket"] blocks without a host condition are
     * skipped — we cannot derive a domain from them.
     *
     * @return array<int, array<string, mixed>>
     */
    private static function parseLighttpd(string $content, string $file): array
    {
        $sites = [];

        // $HTTP["host"] == "example.com" { … }
        if (preg_match_all(
            '/\$HTTP\["host"\]\s*(==|=~)\s*"([^"]+)"\s*\{(.*?)\n\}/si',
            $content,
            $matches,
            PREG_SET_ORDER
        )) {
            foreach ($matches as $m) {
                $domain = $m[2];
                $block  = $m[3];

                preg_match('/server\.document-root\s*=\s*"([^"]+)"/i', $block, $drm);
                $docroot = $drm[1] ?? null;

                $sites[] = [
                    'domain'      => $domain,
                    'config'      => basename($file),
                    'config_path' => $file,
                    'ssl'         => false, // lighttpd SSL is configured globally per socket
                    'ssl_cert'    => null,
                    'docroot'     => $docroot,
                ];
            }
        }

        return $sites;
    }

    /**
     * Parse an nginx-unit configuration JSON.
     *
     * Schema:
     *   {
     *     "listeners": { "*:80": { "pass": "applications/php" } },
     *     "applications": { "php": { "root": "/var/www/example.com" } }
     *   }
     *
     * Domain derivation is best-effort — unit has no vhost concept.
     * If we find a single `root` per application we surface it as
     * `docroot` and synthesise a hostname from the application name
     * (or fall back to the unit config filename stem).
     *
     * @return array<int, array<string, mixed>>
     */
    private static function parseNginxUnit(string $content, string $file): array
    {
        $sites = [];

        $json = json_decode($content, true);
        if (!is_array($json)) {
            return $sites;
        }

        $apps     = is_array($json['applications'] ?? null) ? $json['applications'] : [];
        $fallback = pathinfo($file, PATHINFO_FILENAME);

        foreach ($apps as $appName => $appConf) {
            if (!is_array($appConf)) {
                continue;
            }
            $docroot = null;
            foreach (['root', 'share', 'document_root'] as $key) {
                if (isset($appConf[$key]) && is_string($appConf[$key]) && $appConf[$key] !== '') {
                    $docroot = $appConf[$key];
                    break;
                }
            }
            if ($docroot === null) {
                continue;
            }

            $sites[] = [
                'domain'      => $appName !== '' ? $appName : $fallback,
                'config'      => basename($file),
                'config_path' => $file,
                'ssl'         => false,
                'ssl_cert'    => null,
                'docroot'     => $docroot,
            ];
        }

        return $sites;
    }
}