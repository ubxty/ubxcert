<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Throwable;
use Ubxty\UbxCert\Acme\AcmeClient;

/**
 * ubxcert request
 *
 * Creates a new ACME order, computes DNS-01 challenge TXT values, and
 * persists full order state to disk so `ubxcert complete` can resume it.
 *
 * Usage:
 *   ubxcert request --domains "*.example.com,example.com" --email admin@example.com
 *   ubxcert request --domains "*.example.com,example.com" --email admin@example.com --json
 *   ubxcert request --domains "*.example.com,example.com" --email admin@example.com --staging --force
 */
class RequestCommand extends BaseCommand
{
    public function getName(): string        { return 'request'; }
    public function getDescription(): string { return 'Create ACME order and output DNS-01 challenge info'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domainsRaw = $this->extractOption($args, 'domains');
        $email      = $this->extractOption($args, 'email');
        $force      = $this->hasFlag($args, 'force');

        if (!$domainsRaw || !$email) {
            $this->fail('Usage: ubxcert request --domains "*.example.com,example.com" --email admin@example.com [--staging] [--force] [--json]');
            return 1;
        }

        $domains    = array_map('trim', explode(',', $domainsRaw));
        $baseDomain = $this->extractBaseDomain($domains);

        $this->out("Requesting ACME DNS-01 challenge for: " . implode(', ', $domains));
        $this->out($this->staging ? '[STAGING mode]' : '[PRODUCTION Let\'s Encrypt]');

        // --- Check for existing valid order (unless --force) ----------------
        if (!$force) {
            $existing = $this->state->loadOrderState($baseDomain);
            if ($existing && in_array($existing['order_status'] ?? '', ['pending', 'ready'], true)) {
                $this->out("Existing pending order found. Use --force to create a new one.");
                return $this->outputChallenges($existing);
            }
        }

        // --- Resolve ACME account -------------------------------------------
        try {
            [$jws, $kid, $client] = $this->resolveAccount($email);
        } catch (Throwable $e) {
            $this->fail("Account setup failed: " . $e->getMessage());
            return 1;
        }

        // --- Create order ----------------------------------------------------
        try {
            $this->verbose('Creating ACME order...');
            $order = $client->newOrder($jws, $kid, $domains);
            $this->verbose("Order URL: {$order['order_url']}");
        } catch (Throwable $e) {
            $this->fail("New order failed: " . $e->getMessage());
            return 1;
        }

        // --- Fetch authorizations and compute TXT values --------------------
        $challenges = [];

        foreach ($order['authorizations'] as $authzUrl) {
            try {
                $authz   = $client->getAuthorization($jws, $kid, $authzUrl);
                $domain  = $authz['identifier']['value'];
                $dns01   = null;

                foreach ($authz['challenges'] ?? [] as $chall) {
                    if ($chall['type'] === 'dns-01') {
                        $dns01 = $chall;
                        break;
                    }
                }

                if ($dns01 === null) {
                    $this->fail("No dns-01 challenge found for domain: {$domain}");
                    return 1;
                }

                // Wildcard *.example.com → challenge host _acme-challenge.example.com
                $challengeBase = ltrim($domain, '*.');
                $challengeHost = "_acme-challenge.{$challengeBase}";
                $txtValue      = $jws->computeDnsTxtValue($dns01['token']);

                $challenges[] = [
                    'domain'         => $domain,
                    'challenge_host' => $challengeHost,
                    'txt_value'      => $txtValue,
                    'token'          => $dns01['token'],
                    'challenge_url'  => $dns01['url'],
                    'authz_url'      => $authzUrl,
                    'status'         => $authz['status'],
                ];

                $this->verbose("Challenge for {$domain}: host={$challengeHost}");
            } catch (Throwable $e) {
                $this->fail("Authorization fetch failed: " . $e->getMessage());
                return 1;
            }
        }

        // --- Generate the certificate private key and save state ------------
        try {
            $this->certs->generateCertKey($baseDomain);
        } catch (Throwable $e) {
            $this->fail("Certificate key generation failed: " . $e->getMessage());
            return 1;
        }

        $state = [
            'domain'         => $baseDomain,
            'domains'        => $domains,
            'email'          => $email,
            'staging'        => $this->staging,
            'account_dir'    => $this->state->getAccountDir($email),
            'kid'            => $kid,
            'order_url'      => $order['order_url'],
            'finalize_url'   => $order['finalize'],
            'certificate_url'=> null,
            'cert_key_path'  => $this->state->getOrderCertKeyPath($baseDomain),
            'challenges'     => $challenges,
            'order_status'   => $order['status'],
            'created_at'     => date('c'),
            'completed_at'   => null,
        ];

        $this->state->saveOrderState($baseDomain, $state);
        $this->verbose("Order state saved to: " . $this->state->getOrderDir($baseDomain) . '/state.json');

        return $this->outputChallenges($state);
    }

    // -------------------------------------------------------------------------
    // Output
    // -------------------------------------------------------------------------

    private function outputChallenges(array $state): int
    {
        if ($this->jsonMode) {
            $this->outputJson($this->buildChallengeOutput($state));
            return 0;
        }

        $this->out('');
        $this->out('╔══════════════════════════════════════════════════════════╗');
        $this->out('║          DNS-01 Challenge — Add These TXT Records        ║');
        $this->out('╚══════════════════════════════════════════════════════════╝');

        $seen = [];
        foreach ($state['challenges'] as $c) {
            $key = $c['challenge_host'] . '|' . $c['txt_value'];
            if (in_array($key, $seen, true)) {
                continue;
            }
            $seen[] = $key;

            $this->out('');
            $this->out("  Domain       : {$c['domain']}");
            $this->out("  TXT Name     : {$c['challenge_host']}");
            $this->out("  TXT Value    : {$c['txt_value']}");
        }

        $this->out('');
        $this->out("Add the TXT record(s) above to DNS, then run:");
        $this->out("  ubxcert complete --domain {$state['domain']} --wait-dns 600" . ($this->staging ? ' --staging' : ''));
        $this->out('');

        return 0;
    }

    private function buildChallengeOutput(array $state): array
    {
        return [
            'domain'       => $state['domain'],
            'domains'      => $state['domains'],
            'staging'      => $state['staging'],
            'order_status' => $state['order_status'],
            'challenges'   => array_map(fn($c) => [
                'domain'         => $c['domain'],
                'challenge_host' => $c['challenge_host'],
                'txt_value'      => $c['txt_value'],
                'token'          => $c['token'],
                'status'         => $c['status'],
            ], $state['challenges']),
            'state_path'   => $this->state->getOrderDir($state['domain']) . '/state.json',
            'next_step'    => "ubxcert complete --domain {$state['domain']}" . ($state['staging'] ? ' --staging' : ''),
        ];
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function extractBaseDomain(array $domains): string
    {
        foreach ($domains as $d) {
            if (!str_starts_with($d, '*.')) {
                return $d;
            }
        }
        return ltrim($domains[0], '*.');
    }
}
