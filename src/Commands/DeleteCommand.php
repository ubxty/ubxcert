<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Throwable;

/**
 * ubxcert delete
 *
 * Delete a certificate and/or its order state. Idempotent: returns
 * success (exit 0) when there's nothing to delete, so a script can
 * call this without pre-checking existence. By default the cert
 * files AND the order state are removed; pass --keep-cert to
 * preserve the cert while clearing the state, or --keep-state to
 * preserve the state while clearing the cert.
 *
 * Pass --purge to also remove the certbot-compat symlink dir
 * (/etc/letsencrypt/live/<domain>/) and renewal config
 * (/etc/letsencrypt/renewal/<domain>.conf). This makes a clean
 * handoff to certbot if the operator later wants to manage the
 * same domain with certbot.
 *
 * Pass --certbot to ALSO invoke `certbot delete --cert-name
 * <domain>` for domains that were originally issued by certbot
 * (pre-ubxcert installs). ubxcert will report whatever certbot
 * reports; the exit code is 0 as long as one of the two paths
 * succeeded or there was nothing to do.
 *
 * Pass --all to delete every domain under
 * /etc/ubxcert/certs/ and /etc/ubxcert/orders/. Useful for
 * post-migration cleanup or full reset.
 *
 * Usage:
 *   ubxcert delete --domain example.com
 *   ubxcert delete --domain example.com --purge
 *   ubxcert delete --domain example.com --keep-cert
 *   ubxcert delete --domain example.com --certbot
 *   ubxcert delete --all
 *   ubxcert delete --all --purge --json
 */
class DeleteCommand extends BaseCommand
{
    private const CERTBOT_LIVE_DIR  = '/etc/letsencrypt/live';
    private const CERTBOT_RENEW_DIR = '/etc/letsencrypt/renewal';

    public function getName(): string        { return 'delete'; }
    public function getDescription(): string { return 'Delete a certificate and its order state (idempotent, supports bulk)'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domain    = $this->extractOption($args, 'domain');
        $all       = $this->hasFlag($args, 'all');
        $purge     = $this->hasFlag($args, 'purge');
        $keepCert  = $this->hasFlag($args, 'keep-cert');
        $keepState = $this->hasFlag($args, 'keep-state');
        $useCertbot = $this->hasFlag($args, 'certbot');
        $force     = $this->hasFlag($args, 'force');

        if (!$all && !$domain) {
            $this->fail('Usage: ubxcert delete --domain <domain> [--purge] [--keep-cert|--keep-state] [--certbot] [--json]');
            $this->fail('   or: ubxcert delete --all [--purge] [--certbot] [--json]');
            return 1;
        }

        if ($all && $domain) {
            $this->fail('Cannot combine --domain with --all.');
            return 1;
        }

        if ($keepCert && $keepState) {
            $this->fail('Cannot combine --keep-cert with --keep-state (would delete nothing).');
            return 1;
        }

        $domains = $all ? $this->collectAllDomains() : [$domain];

        $summary = [
            'command'    => 'delete',
            'domains'    => [],
            'all'        => $all,
            'purge'      => $purge,
            'keep_cert'  => $keepCert,
            'keep_state' => $keepState,
            'certbot'    => $useCertbot,
        ];

        $anyError = false;

        foreach ($domains as $d) {
            $result = $this->deleteOne($d, $purge, $keepCert, $keepState, $useCertbot);
            $summary['domains'][] = $result;
            if (!empty($result['errors'])) {
                $anyError = true;
            }
        }

        $summary['succeeded'] = !$anyError;
        $summary['deleted_count'] = count(array_filter(
            $summary['domains'],
            fn($r) => ($r['cert_removed_count'] ?? 0) > 0 || ($r['state_removed_count'] ?? 0) > 0 || ($r['certbot_invoked'] ?? false)
        ));
        $summary['noop_count'] = count($domains) - $summary['deleted_count'];

        if ($this->jsonMode) {
            $this->outputJson($summary);
        }

        // Exit 0 if every domain either succeeded or was a no-op.
        // Exit 1 only if a real error occurred (unreadable dir,
        // certbot not installed when --certbot was requested, etc).
        return $anyError ? 1 : 0;
    }

    /**
     * @return string[] sorted, de-duplicated union of every domain
     *   that has either a cert dir or an order state dir.
     */
    private function collectAllDomains(): array
    {
        $certs  = $this->state->listCertDomains();
        $orders = [];
        $ordersBase = $this->state->getBaseDir() . '/orders';
        if (is_dir($ordersBase)) {
            foreach (glob($ordersBase . '/*', GLOB_ONLYDIR) ?: [] as $dir) {
                $orders[] = basename($dir);
            }
        }
        $all = array_unique(array_merge($certs, $orders));
        sort($all);
        return $all;
    }

    private function deleteOne(string $domain, bool $purge, bool $keepCert, bool $keepState, bool $useCertbot): array
    {
        $result = [
            'domain'              => $domain,
            'cert_removed'        => [],
            'state_removed'       => [],
            'purge_removed'       => [],
            'certbot_invoked'     => false,
            'certbot_message'     => null,
            'cert_removed_count'  => 0,
            'state_removed_count' => 0,
            'errors'              => [],
        ];

        // Cert files
        if (!$keepCert) {
            try {
                $removed = $this->state->deleteCertDir($domain);
                $result['cert_removed'] = $removed;
                $result['cert_removed_count'] = count($removed);
                if ($removed && !$this->jsonMode) {
                    $this->success("Removed cert dir contents for {$domain} (" . count($removed) . " entries)");
                }
            } catch (Throwable $e) {
                $result['errors'][] = "cert: " . $e->getMessage();
            }
        }

        // Order state
        if (!$keepState) {
            try {
                $before = $this->state->loadOrderState($domain);
                $orderDir = $this->state->getOrderDir($domain);
                // Snapshot which files exist BEFORE the delete,
                // so we can honestly report what was actually
                // removed (vs. what never existed). file_exists()
                // post-delete would conflate "deleted" with
                // "never existed".
                $presentBefore = array_values(array_filter(
                    [$orderDir . '/state.json', $orderDir . '/cert.key'],
                    'file_exists'
                ));
                $this->state->deleteOrderState($domain);
                if ($before || $presentBefore) {
                    $result['state_removed']      = $presentBefore;
                    $result['state_removed_count'] = count($presentBefore);
                    if ($presentBefore && !$this->jsonMode) {
                        $this->success("Cleared order state for {$domain}");
                    }
                }
            } catch (Throwable $e) {
                $result['errors'][] = "state: " . $e->getMessage();
            }
        }

        // Purge = certbot-compat symlinks
        if ($purge) {
            try {
                $liveLink = self::CERTBOT_LIVE_DIR . '/' . $domain;
                $renewConf = self::CERTBOT_RENEW_DIR . '/' . $domain . '.conf';
                if (is_link($liveLink) || is_dir($liveLink)) {
                    // /etc/letsencrypt/live/<domain> is itself a
                    // symlink to /etc/ubxcert/certs/<domain>
                    // (per install command). Just remove the
                    // symlink; don't follow it.
                    if (@unlink($liveLink)) {
                        $result['purge_removed'][] = $liveLink;
                    }
                }
                if (is_file($renewConf)) {
                    if (@unlink($renewConf)) {
                        $result['purge_removed'][] = $renewConf;
                    }
                }
                if ($result['purge_removed'] && !$this->jsonMode) {
                    $this->success("Purged certbot symlinks for {$domain} (" . count($result['purge_removed']) . " entries)");
                }
            } catch (Throwable $e) {
                $result['errors'][] = "purge: " . $e->getMessage();
            }
        }

        // Optional certbot delegation
        if ($useCertbot) {
            $certbot = $this->findCertbot();
            if ($certbot === null) {
                $result['errors'][] = "certbot binary not found on PATH";
            } else {
                $result['certbot_invoked'] = true;
                $cmd = "{$certbot} delete --cert-name " . escapeshellarg($domain) . " 2>&1";
                $output  = [];
                $rc      = 0;
                exec($cmd, $output, $rc);
                $result['certbot_message'] = trim(implode("\n", $output));
                if ($rc !== 0 && stripos($result['certbot_message'], 'not found') === false) {
                    // certbot returns non-zero when the cert
                    // doesn't exist; treat that as a successful
                    // no-op for parity with ubxcert's own
                    // idempotent semantics.
                    $result['errors'][] = "certbot exit {$rc}: " . $result['certbot_message'];
                }
            }
        }

        return $result;
    }

    private function findCertbot(): ?string
    {
        $candidates = ['/usr/bin/certbot', '/usr/local/bin/certbot'];
        foreach ($candidates as $c) {
            if (is_executable($c)) {
                return $c;
            }
        }
        // Fall back to PATH
        $path = trim((string) shell_exec('command -v certbot 2>/dev/null'));
        return $path !== '' ? $path : null;
    }
}
