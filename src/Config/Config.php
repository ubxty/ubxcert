<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Config;

/**
 * Box-level configuration for ubxcert.
 *
 * Reads /etc/ubxcert/config.json (if present) and exposes typed
 * accessors. The file is created via `ubxcert install` and can be
 * hand-edited by the operator. Missing keys fall back to safe defaults.
 *
 * Supported keys:
 *   - default_staging (bool): always talk to Let's Encrypt staging
 *     unless overridden by --staging/--no-staging on the command line.
 *   - log_level (string): "info" | "warn" | "error". Default "info".
 *   - renewal_days_before (int): --days-before default for cron jobs.
 *   - cloudflare (object): { api_token, zone_id } for DNS-01 automation.
 *
 * Example:
 *   {
 *     "default_staging": false,
 *     "log_level": "info",
 *     "renewal_days_before": 30
 *   }
 */
class Config
{
    private const CONFIG_PATH = '/etc/ubxcert/config.json';

    /** @var array<string, mixed> */
    private array $values = [];

    public function __construct(?string $configPath = null)
    {
        $this->load($configPath ?? self::CONFIG_PATH);
    }

    /**
     * Read a config value with an optional default. Returns the
     * default if the key is missing or the file is unreadable.
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->values[$key] ?? $default;
    }

    /**
     * Set a value in-memory. Does not persist to disk.
     */
    public function set(string $key, mixed $value): void
    {
        $this->values[$key] = $value;
    }

    /**
     * Returns the full in-memory config as an array.
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->values;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }

    /**
     * Persist the current in-memory config to disk. Creates the
     * directory if missing. Sets 0600 permissions on the file.
     */
    public function save(): bool
    {
        $path = self::CONFIG_PATH;
        $dir  = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            return false;
        }
        $json = json_encode($this->values, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $ok   = file_put_contents($path, $json) !== false;
        if ($ok) {
            chmod($path, 0600);
        }
        return $ok;
    }

    private function load(string $path): void
    {
        if (!file_exists($path)) {
            return;
        }
        $raw = @file_get_contents($path);
        if ($raw === false || $raw === '') {
            return;
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return;
        }
        $this->values = $decoded;
    }
}
