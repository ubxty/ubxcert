<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Ubxty\UbxCert\Util\VhostScanner;

/**
 * ubxcert scan
 *
 * Diagnostic command — shows every .conf file in all webserver config
 * directories, whether it was readable, and what domains were parsed from it.
 *
 * Useful for debugging "why isn't domain X showing up?" issues.
 *
 * Usage:
 *   ubxcert scan
 *   ubxcert scan --json
 */
class ScanCommand extends BaseCommand
{
    public function getName(): string        { return 'scan'; }
    public function getDescription(): string { return 'Diagnostic: show all vhost config files and parsed domains'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $results = [];

        foreach (VhostScanner::CONF_DIRS as $ws => $dirs) {
            foreach ($dirs as $dir) {
                if (!is_dir($dir)) {
                    $results[] = ['webserver' => $ws, 'dir' => $dir, 'status' => 'missing', 'files' => []];
                    continue;
                }

                $files = [];
                foreach (glob($dir . '/*.conf') ?: [] as $file) {
                    if (!is_readable($file)) {
                        $files[] = ['file' => $file, 'readable' => false, 'domains' => []];
                        continue;
                    }

                    $content = file_get_contents($file);
                    if ($content === false) {
                        $files[] = ['file' => $file, 'readable' => false, 'domains' => []];
                        continue;
                    }

                    // Parse using the same logic as VhostScanner
                    $entries = $ws === 'apache'
                        ? $this->parseApache($content)
                        : $this->parseNginx($content);

                    $files[] = [
                        'file'     => $file,
                        'readable' => true,
                        'domains'  => array_column($entries, 'domain'),
                        'fallback' => empty($entries),
                        'size'     => strlen($content),
                    ];
                }

                $results[] = ['webserver' => $ws, 'dir' => $dir, 'status' => 'found', 'files' => $files];
            }
        }

        if ($this->jsonMode) {
            $this->outputJson($results);
            return 0;
        }

        echo "\n  \033[1mubxcert scan — vhost config diagnostic\033[0m\n\n";

        foreach ($results as $group) {
            $ws  = $group['webserver'];
            $dir = $group['dir'];

            if ($group['status'] === 'missing') {
                echo "  \033[90m{$ws}  {$dir}  (directory not found)\033[0m\n";
                continue;
            }

            echo "  \033[1m{$ws}\033[0m  \033[2m{$dir}\033[0m\n";
            echo '  ' . str_repeat('─', 80) . "\n";

            if (empty($group['files'])) {
                echo "  \033[33m  (no .conf files found)\033[0m\n\n";
                continue;
            }

            foreach ($group['files'] as $f) {
                if (!$f['readable']) {
                    echo "  \033[31m  ✗ (unreadable)\033[0m  {$f['file']}\n";
                    continue;
                }

                $domainStr = empty($f['domains'])
                    ? "\033[33m(no domains parsed)\033[0m"
                    : implode(', ', $f['domains']);

                $fallbackNote = $f['fallback'] ? ' \033[33m[filename fallback]\033[0m' : '';
                $sizeNote     = "  \033[2m[{$f['size']} bytes]\033[0m";

                printf(
                    "  \033[32m  %-50s\033[0m  %s%s%s\n",
                    basename($f['file']),
                    $domainStr,
                    $fallbackNote,
                    $sizeNote
                );
            }

            echo "\n";
        }

        return 0;
    }

    // -------------------------------------------------------------------------
    // Lightweight parsers (duplicated from VhostScanner via brace-counter)
    // -------------------------------------------------------------------------

    /** @return array<int, array{domain: string}> */
    private function parseNginx(string $content): array
    {
        $stripped = preg_replace('/#[^\n]*/', '', $content) ?? $content;
        $sites    = [];
        $offset   = 0;
        $len      = strlen($stripped);

        while ($offset < $len) {
            if (!preg_match('/\bserver\s*\{/s', $stripped, $m, PREG_OFFSET_CAPTURE, $offset)) {
                break;
            }
            $start = $m[0][1] + strlen($m[0][0]);
            $depth = 1;
            $pos   = $start;
            while ($pos < $len && $depth > 0) {
                $ch = $stripped[$pos];
                if ($ch === '{') {
                    $depth++;
                } elseif ($ch === '}') {
                    $depth--;
                }
                $pos++;
            }
            if ($depth === 0) {
                $block = substr($stripped, $start, $pos - $start - 1);
                preg_match('/\bserver_name\s+([^;]+);/', $block, $snm);
                if ($snm) {
                    foreach (array_filter(preg_split('/\s+/', trim($snm[1])) ?: []) as $name) {
                        $name = ltrim((string) $name, '.');
                        if ($name !== '_' && $name !== '') {
                            $sites[] = ['domain' => $name];
                        }
                    }
                }
            }
            $offset = $pos;
        }

        return $sites;
    }

    /** @return array<int, array{domain: string}> */
    private function parseApache(string $content): array
    {
        preg_match_all('/<VirtualHost[^>]*>(.*?)<\/VirtualHost>/si', $content, $m);
        $sites = [];
        foreach ($m[1] ?? [] as $block) {
            preg_match('/^\s*ServerName\s+(\S+)/mi', $block, $snm);
            if ($snm) {
                $sites[] = ['domain' => trim($snm[1])];
            }
        }
        return $sites;
    }
}
