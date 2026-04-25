<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Ubxty\UbxCert\Application;

/**
 * ubxcert self-update
 *
 * Fetches the latest version from GitHub, runs the install script, and
 * replaces the current binary in-place.
 *
 * What it does:
 *   1. Fetches the latest git tag from GitHub API
 *   2. Compares it against the running VERSION
 *   3. If newer (or --force is given), pulls install-ubxcert.sh and runs it
 *   4. Exits with 0 on success, 1 on failure
 *
 * Usage:
 *   ubxcert self-update
 *   ubxcert self-update --force          (re-install even if already up-to-date)
 *   ubxcert self-update --check          (check only — print version info, do not install)
 *   ubxcert self-update --json
 */
class SelfUpdateCommand extends BaseCommand
{
    /** Raw URL for install script — must be HTTPS */
    private const INSTALL_SCRIPT_URL = 'https://raw.githubusercontent.com/ubxty/ubxcert/main/install-ubxcert.sh';

    /** GitHub API endpoint for latest release tag */
    private const RELEASES_API_URL = 'https://api.github.com/repos/ubxty/ubxcert/releases/latest';

    /** Fallback: list of git tags endpoint */
    private const TAGS_API_URL = 'https://api.github.com/repos/ubxty/ubxcert/tags';

    /** Set to true once any HTTP request receives any response (even 4xx) from GitHub */
    private bool $githubReachable = false;

    public function getName(): string        { return 'self-update'; }
    public function getDescription(): string { return 'Update ubxcert to the latest version from GitHub'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $force     = $this->hasFlag($args, 'force');
        $checkOnly = $this->hasFlag($args, 'check');

        $current = $this->getCurrentVersion();
        $latest  = $this->fetchLatestVersion();

        if ($latest === null) {
            if ($this->githubReachable) {
                // GitHub responded but no releases/tags have been published yet.
                // Just run the install script which always pulls the latest main branch.
                if ($checkOnly) {
                    if ($this->jsonMode) {
                        $this->outputJson(['current_version' => $current, 'latest_version' => null, 'note' => 'No releases published yet']);
                    } else {
                        $this->out("\n  \033[2mNo releases published yet. ubxcert tracks the latest main branch.\033[0m\n");
                    }
                    return 0;
                }
                if (!$this->jsonMode) {
                    $this->out("  No version tags found — installing from latest main branch...\n");
                }
                return $this->runInstall('latest');
            }

            if ($this->jsonMode) {
                $this->outputJson(['error' => 'Could not reach GitHub API to check for updates']);
            } else {
                $this->warn('Could not reach GitHub to check for updates.');
                $this->out('Check your internet connection and try again.');
            }
            return 1;
        }

        $isNewer = $this->isNewer($latest, $current);

        if ($this->jsonMode) {
            $this->outputJson([
                'current_version' => $current,
                'latest_version'  => $latest,
                'update_available' => $isNewer,
                'action'          => $checkOnly ? 'check' : ($force || $isNewer ? 'update' : 'none'),
            ]);

            if ($checkOnly) {
                return 0;
            }
        } else {
            $this->printVersionInfo($current, $latest, $isNewer);

            if ($checkOnly) {
                return 0;
            }
        }

        if (!$isNewer && !$force) {
            if (!$this->jsonMode) {
                $this->success("ubxcert is already up-to-date (v{$current}).");
            }
            return 0;
        }

        // Need root to write /opt/ubxcert and /usr/local/bin/ubxcert
        $uid = function_exists('posix_getuid') ? posix_getuid() : (int) trim((string) shell_exec('id -u'));
        if ($uid !== 0) {
            if (!$this->jsonMode) {
                echo "\n  \033[31mRoot required.\033[0m  Run:\n";
                echo "    sudo ubxcert self-update\n\n";
            }
            return 1;
        }

        return $this->runInstall($latest);
    }

    // -------------------------------------------------------------------------
    // Version helpers
    // -------------------------------------------------------------------------

    private function getCurrentVersion(): string
    {
        // Try reading VERSION file next to the binary/install dir first
        foreach (['/opt/ubxcert/VERSION', dirname(__DIR__, 2) . '/VERSION'] as $vf) {
            if (is_file($vf)) {
                $v = trim((string) file_get_contents($vf));
                if ($v !== '') {
                    return ltrim($v, 'v');
                }
            }
        }

        // Fallback: git describe from install dir
        $out = [];
        exec('git -C /opt/ubxcert describe --tags --abbrev=0 2>/dev/null', $out, $rc);
        if ($rc === 0 && !empty($out[0])) {
            return ltrim(trim($out[0]), 'v');
        }

        return Application::getVersion();
    }

    private function fetchLatestVersion(): ?string
    {
        // Try GitHub releases API first
        $json = $this->httpGet(self::RELEASES_API_URL);
        if ($json !== null) {
            $data = @json_decode($json, true);
            if (is_array($data) && isset($data['tag_name'])) {
                return ltrim(trim($data['tag_name']), 'v');
            }
        }

        // Fallback: tags API (first tag is the latest)
        $json = $this->httpGet(self::TAGS_API_URL);
        if ($json !== null) {
            $data = @json_decode($json, true);
            if (is_array($data) && isset($data[0]['name'])) {
                return ltrim(trim($data[0]['name']), 'v');
            }
        }

        return null;
    }

    /**
     * Returns true if $latest is strictly newer than $current
     * using PHP's version_compare.
     */
    private function isNewer(string $latest, string $current): bool
    {
        return version_compare($latest, $current, '>');
    }

    // -------------------------------------------------------------------------
    // Output helpers
    // -------------------------------------------------------------------------

    private function printVersionInfo(string $current, string $latest, bool $isNewer): void
    {
        echo "\n";
        echo "  \033[1mubxcert version check\033[0m\n";
        echo '  ' . str_repeat('─', 44) . "\n";
        printf("  Installed : \033[36mv%s\033[0m\n", $current);
        printf("  Latest    : \033[36mv%s\033[0m\n", $latest);

        if ($isNewer) {
            echo "\n  \033[32m✓ New version available!\033[0m\n";
        } else {
            echo "\n  \033[2mYou are running the latest version.\033[0m\n";
        }
        echo "\n";
    }

    // -------------------------------------------------------------------------
    // Install
    // -------------------------------------------------------------------------

    private function runInstall(string $version): int
    {
        $this->out("Updating to v{$version}...\n");

        // Download install script to a temp file
        $tmp = '/tmp/ubxcert-install-' . bin2hex(random_bytes(4)) . '.sh';

        $script = $this->httpGet(self::INSTALL_SCRIPT_URL);
        if ($script === null) {
            $this->fail('Failed to download install script from GitHub.');
            return 1;
        }

        if (file_put_contents($tmp, $script) === false) {
            $this->fail("Cannot write temporary file: {$tmp}");
            return 1;
        }

        chmod($tmp, 0700);

        // Stream install script output directly — popen/fgets causes buffering
        // stalls with long-running subprocesses like composer install.
        $ret = 0;
        passthru("bash {$tmp}", $ret);

        @unlink($tmp);

        if ($ret !== 0) {
            $this->fail("Install script exited with code {$ret}.");
            return 1;
        }

        // Verify the new version was installed
        $newVer = $this->getCurrentVersion();
        $this->success("ubxcert updated to v{$newVer}.");
        return 0;
    }

    // -------------------------------------------------------------------------
    // HTTP helper (uses curl extension or falls back to file_get_contents)
    // -------------------------------------------------------------------------

    private function httpGet(string $url): ?string
    {
        if (extension_loaded('curl')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_TIMEOUT        => 15,
                CURLOPT_USERAGENT      => 'ubxcert-self-update/1.0',
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            $body = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($body !== false && $code > 0) {
                $this->githubReachable = true;
            }
            if ($body !== false && $code >= 200 && $code < 300) {
                return (string) $body;
            }
            return null;
        }

        // Fallback
        $ctx = stream_context_create([
            'http' => [
                'timeout'       => 15,
                'user_agent'    => 'ubxcert-self-update/1.0',
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer'       => true,
                'verify_peer_name'  => true,
            ],
        ]);

        $body = @file_get_contents($url, false, $ctx);
        if ($body !== false) {
            $this->githubReachable = true;
            return $body;
        }
        return null;
    }
}
