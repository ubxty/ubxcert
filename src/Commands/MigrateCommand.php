<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

/**
 * ubxcert migrate
 *
 * Migrates certbot-managed certificates into ubxcert management so they
 * will be renewed by `ubxcert renew --all` instead of certbot.
 *
 * What it does per domain:
 *   1. Copies PEM files from /etc/letsencrypt/live/<domain>/ → /etc/ubxcert/certs/<domain>/
 *   2. Creates a minimal order state.json so ubxcert tracks the cert
 *   3. Updates /etc/letsencrypt/live/<domain>/ symlinks to point to the copied files
 *   4. Does NOT touch certbot's archive — your original files are preserved
 *
 * Usage:
 *   ubxcert migrate --all [--email admin@example.com] [--dry-run]
 *   ubxcert migrate --domain example.com [--email admin@example.com] [--dry-run]
 */
class MigrateCommand extends BaseCommand
{
    private const LE_LIVE = '/etc/letsencrypt/live';

    public function getName(): string        { return 'migrate'; }
    public function getDescription(): string { return 'Migrate certbot certificates to ubxcert management'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $all     = $this->hasFlag($args, 'all');
        $domain  = $this->extractOption($args, 'domain');
        $email   = $this->extractOption($args, 'email') ?? 'migrated@ubxcert.local';
        $dryRun  = $this->hasFlag($args, 'dry-run');

        if (!$all && !$domain) {
            $this->fail('Usage: ubxcert migrate --all | --domain example.com [--email you@example.com] [--dry-run]');
            return 1;
        }

        $domains = $domain ? [$domain] : $this->discoverCertbotDomains();

        if (empty($domains)) {
            $this->out('No certbot certificates found in ' . self::LE_LIVE . '/');
            return 0;
        }

        if ($dryRun) {
            $this->out("\033[33m[DRY RUN]\033[0m No files will be written.\n");
        }

        $migrated = 0;
        $skipped  = 0;
        $failed   = 0;

        foreach ($domains as $dom) {
            $result = $this->migrateDomain($dom, $email, $dryRun);
            match ($result) {
                'migrated' => $migrated++,
                'skipped'  => $skipped++,
                default    => $failed++,
            };
        }

        echo "\n";
        $this->out("Migration complete: migrated={$migrated}, skipped={$skipped}, failed={$failed}");

        if ($migrated > 0 && !$dryRun) {
            echo "\n";
            $this->success("Certificates are now managed by ubxcert.");
            $this->out("Run \033[36mubxcert list\033[0m to verify, then test renewal with:");
            $this->out("  ubxcert renew --all --days-before 999   (forces re-check)");
        }

        return $failed > 0 ? 1 : 0;
    }

    // -------------------------------------------------------------------------
    // Discovery
    // -------------------------------------------------------------------------

    /** @return string[] */
    private function discoverCertbotDomains(): array
    {
        if (!is_dir(self::LE_LIVE)) {
            return [];
        }

        $domains = [];
        foreach (glob(self::LE_LIVE . '/*/cert.pem') ?: [] as $certPath) {
            $dom = basename(dirname($certPath));
            if ($dom === 'README') {
                continue;
            }
            // Skip if already owned by ubxcert
            if (is_link($certPath)) {
                $target = realpath($certPath);
                if ($target !== false && str_starts_with($target, '/etc/ubxcert/')) {
                    continue;
                }
            }
            $domains[] = $dom;
        }

        return $domains;
    }

    // -------------------------------------------------------------------------
    // Per-domain migration
    // -------------------------------------------------------------------------

    private function migrateDomain(string $domain, string $email, bool $dryRun): string
    {
        $leDir  = self::LE_LIVE . "/{$domain}";
        $files  = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'];

        // Check source exists
        foreach ($files as $f) {
            $src = "{$leDir}/{$f}";
            if (!file_exists($src)) {
                $this->warn("  Skipping {$domain}: {$src} not found.");
                return 'skipped';
            }
        }

        // Already managed by ubxcert?
        if ($this->state->certExists($domain)) {
            $this->out("  SKIP  {$domain}  (already managed by ubxcert)");
            return 'skipped';
        }

        $certDir = $this->state->getCertDir($domain);
        $this->out("  MIGRATING  {$domain}");
        $this->verbose("  Source: {$leDir}/");
        $this->verbose("  Target: {$certDir}/");

        if ($dryRun) {
            $this->out("    \033[2m[dry-run] would copy files + create state.json\033[0m");
            return 'migrated';
        }

        // ── 1. Create cert directory -----------------------------------------
        if (!is_dir($certDir)) {
            if (!mkdir($certDir, 0700, true) && !is_dir($certDir)) {
                $this->fail("  Cannot create directory: {$certDir}");
                return 'failed';
            }
        }

        // ── 2. Resolve symlinks and copy real file content -------------------
        foreach ($files as $f) {
            $src  = realpath("{$leDir}/{$f}") ?: "{$leDir}/{$f}";
            $dest = "{$certDir}/{$f}";

            $content = @file_get_contents($src);
            if ($content === false) {
                $this->fail("  Cannot read {$src}");
                return 'failed';
            }

            if (file_put_contents($dest, $content) === false) {
                $this->fail("  Cannot write {$dest}");
                return 'failed';
            }

            chmod($dest, $f === 'privkey.pem' ? 0600 : 0644);
        }

        // ── 3. Parse cert info -----------------------------------------------
        $pem    = file_get_contents("{$certDir}/cert.pem");
        $cert   = $pem ? @openssl_x509_read($pem) : false;
        $expiry = null;
        $sans   = [$domain];

        if ($cert !== false) {
            $info   = openssl_x509_parse($cert);
            $expiry = $info['validTo_time_t'] ?? null;

            $ext = $info['extensions']['subjectAltName'] ?? '';
            foreach (explode(',', $ext) as $part) {
                $part = trim($part);
                if (str_starts_with($part, 'DNS:')) {
                    $sans[] = ltrim($part, 'DNS:');
                }
            }
            $sans = array_unique($sans);
        }

        // ── 4. Create state.json so ubxcert renew can manage it ─────────────
        $orderDir = $this->state->getOrderDir($domain);
        if (!is_dir($orderDir)) {
            mkdir($orderDir, 0700, true);
        }

        $state = [
            'domain'          => $domain,
            'domains'         => array_values($sans),
            'email'           => $email,
            'staging'         => false,
            'account_dir'     => $this->state->getAccountDir($email),
            'kid'             => null,  // will be set on first renewal
            'order_url'       => null,
            'finalize_url'    => null,
            'certificate_url' => null,
            'cert_key_path'   => $this->state->getOrderCertKeyPath($domain),
            'challenges'      => [],
            'order_status'    => 'valid',
            'source'          => 'migrated_from_certbot',
            'created_at'      => date('c'),
            'completed_at'    => date('c'),
            'cert_expiry'     => $expiry !== null ? gmdate('c', $expiry) : null,
        ];

        $this->state->saveOrderState($domain, $state);

        // ── 5. Update /etc/letsencrypt/live/ symlinks to point at ubxcert ───
        foreach ($files as $f) {
            $link   = "{$leDir}/{$f}";
            $target = "{$certDir}/{$f}";

            if (is_link($link)) {
                unlink($link);
            } elseif (file_exists($link)) {
                rename($link, "{$link}.certbot.bak");
            }

            if (!symlink($target, $link)) {
                $this->warn("  Could not create symlink {$link} → {$target}");
            }
        }

        $expiryStr = $expiry !== null ? gmdate('Y-m-d', $expiry) . ' UTC' : 'unknown';
        $this->success("  Migrated {$domain} (expires: {$expiryStr})");

        return 'migrated';
    }
}
