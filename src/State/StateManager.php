<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\State;

use RuntimeException;

/**
 * File-based state persistence for ACME orders and accounts.
 *
 * Directory structure under /etc/ubxcert/:
 *   accounts/{sanitized-email}/
 *     account.json    — KID, email, created_at
 *     private.pem     — RSA account key
 *   orders/{domain}/
 *     state.json      — full order state (challenges, URLs, status)
 *     cert.key        — certificate private key (generated during request)
 *   certs/{domain}/
 *     fullchain.pem, cert.pem, chain.pem, privkey.pem
 */
class StateManager
{
    /**
     * Default base directory for state. Overridable for testing
     * via the constructor. Production code should not change this
     * — the install-ubxcert.sh installer assumes /etc/ubxcert.
     */
    private const DEFAULT_BASE_DIR = '/etc/ubxcert';

    private string $baseDir;

    public function __construct(?string $baseDir = null)
    {
        $this->baseDir = $baseDir ?? self::DEFAULT_BASE_DIR;
    }

    public function getBaseDir(): string
    {
        return $this->baseDir;
    }

    // -------------------------------------------------------------------------
    // Account helpers
    // -------------------------------------------------------------------------

    public function getAccountDir(string $email): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9._-]/', '-', $email);
        return $this->baseDir . "/accounts/{$safe}";
    }

    public function getAccountKeyPath(string $email): string
    {
        return $this->getAccountDir($email) . '/private.pem';
    }

    public function saveAccountInfo(string $email, array $info): void
    {
        $dir = $this->getAccountDir($email);
        $this->ensureDir($dir, 0700);
        $this->writeJson($dir . '/account.json', $info);
    }

    public function loadAccountInfo(string $email): ?array
    {
        $path = $this->getAccountDir($email) . '/account.json';
        return file_exists($path) ? json_decode(file_get_contents($path), true) : null;
    }

    public function accountExists(string $email): bool
    {
        return file_exists($this->getAccountKeyPath($email))
            && file_exists($this->getAccountDir($email) . '/account.json');
    }

    // -------------------------------------------------------------------------
    // Order helpers
    // -------------------------------------------------------------------------

    public function getOrderDir(string $domain): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9._-]/', '-', $domain);
        return $this->baseDir . "/orders/{$safe}";
    }

    public function getOrderCertKeyPath(string $domain): string
    {
        return $this->getOrderDir($domain) . '/cert.key';
    }

    public function saveOrderState(string $domain, array $state): void
    {
        $dir = $this->getOrderDir($domain);
        $this->ensureDir($dir, 0700);
        $this->writeJson($dir . '/state.json', $state);
    }

    public function loadOrderState(string $domain): ?array
    {
        $path = $this->getOrderDir($domain) . '/state.json';
        if (!file_exists($path)) {
            return null;
        }
        return json_decode(file_get_contents($path), true);
    }

    public function orderExists(string $domain): bool
    {
        return file_exists($this->getOrderDir($domain) . '/state.json');
    }

    public function deleteOrderState(string $domain): void
    {
        $dir = $this->getOrderDir($domain);
        if (!is_dir($dir)) {
            return;
        }
        foreach (glob($dir . '/{,.}*', GLOB_BRACE) ?: [] as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        // Best-effort: remove the now-empty dir. Silently skip
        // if it has subdirs or we lack permission.
        @rmdir($dir);
    }

    // -------------------------------------------------------------------------
    // Certificate helpers
    // -------------------------------------------------------------------------

    public function getCertDir(string $domain): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9._-]/', '-', $domain);
        return $this->baseDir . "/certs/{$safe}";
    }

    public function certExists(string $domain): bool
    {
        return file_exists($this->getCertDir($domain) . '/fullchain.pem');
    }

    public function listCertDomains(): array
    {
        $base = $this->baseDir . '/certs';
        if (!is_dir($base)) {
            return [];
        }
        return array_map('basename', glob($base . '/*', GLOB_ONLYDIR) ?: []);
    }

    /**
     * Recursively delete the certificate directory for $domain.
     * Returns the list of file paths that were actually removed
     * (empty if nothing existed). Symlinks are removed, not
     * followed.
     *
     * @return string[]
     */
    public function deleteCertDir(string $domain): array
    {
        $dir = $this->getCertDir($domain);
        if (!is_dir($dir)) {
            return [];
        }
        $removed = [];
        $this->rmTree($dir, $removed);
        return $removed;
    }

    /**
     * Recursive delete that captures what it removed so the caller
     * can report it. Skips entries that cannot be removed so a
     * single permission error doesn't mask other removals.
     */
    private function rmTree(string $path, array &$removed): void
    {
        if (is_link($path) || is_file($path)) {
            if (@unlink($path)) {
                $removed[] = $path;
            }
            return;
        }
        if (!is_dir($path)) {
            return;
        }
        foreach (scandir($path) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $this->rmTree($path . '/' . $entry, $removed);
        }
        if (@rmdir($path)) {
            $removed[] = $path;
        }
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private function ensureDir(string $dir, int $mode = 0755): void
    {
        if (!is_dir($dir) && !mkdir($dir, $mode, true) && !is_dir($dir)) {
            throw new RuntimeException("Cannot create directory: {$dir}");
        }
    }

    private function writeJson(string $path, array $data): void
    {
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        file_put_contents($path, $json);
        chmod($path, 0600);
    }
}
