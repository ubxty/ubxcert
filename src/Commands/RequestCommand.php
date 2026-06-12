<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Throwable;
use Ubxty\UbxCert\Acme\AcmeClient;

/**
 * ubxcert request
 *
 * Creates a new ACME order, computes the chosen challenge values
 * (DNS-01 or HTTP-01), and persists full order state to disk so
 * `ubxcert complete` can resume it.
 *
 * Usage:
 *   ubxcert request --domains "*.example.com,example.com" --email admin@example.com
 *   ubxcert request --domains "example.com" --email admin@example.com --challenge http
 *   ubxcert request --domains "*.example.com,example.com" --email admin@example.com --json
 *   ubxcert request --domains "*.example.com,example.com" --email admin@example.com --staging --force
 */
class RequestCommand extends BaseCommand
{
    private const CHALLENGE_DNS  = 'dns';
    private const CHALLENGE_HTTP = 'http';

    public function getName(): string        { return 'request'; }
    public function getDescription(): string { return 'Create ACME order and output challenge info (DNS-01 or HTTP-01)'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domainsRaw = $this->extractOption($args, 'domains');
        $email      = $this->extractOption($args, 'email');
        $force      = $this->hasFlag($args, 'force');
        $challenge  = strtolower($this->extractOption($args, 'challenge') ?? self::CHALLENGE_DNS);

        if (!$domainsRaw || !$email) {
            $this->fail('Usage: ubxcert request --domains "*.example.com,example.com" --email admin@example.com [--challenge dns|http] [--staging] [--force] [--json]');
            return 1;
        }

        if (!in_array($challenge, [self::CHALLENGE_DNS, self::CHALLENGE_HTTP], true)) {
            $this->fail("Invalid --challenge value '{$challenge}'. Use 'dns' or 'http'.");
            return 1;
        }

        $domains    = array_map('trim', explode(',', $domainsRaw));
        $domains    = array_values(array_filter($domains, fn($d) => $d !== ''));
        $baseDomain = $this->extractBaseDomain($domains);

        // HTTP-01 cannot satisfy wildcard identifiers — RFC 8555 §7.2.
        if ($challenge === self::CHALLENGE_HTTP) {
            foreach ($domains as $d) {
                if (str_starts_with($d, '*.')) {
                    $this->fail("HTTP-01 does not support wildcards. Found: {$d}. Use --challenge dns (default) for wildcard certs.");
                    return 1;
                }
            }
        }

        $challengeLabel = $challenge === self::CHALLENGE_HTTP ? 'HTTP-01' : 'DNS-01';
        $this->out("Requesting ACME {$challengeLabel} challenge for: " . implode(', ', $domains));
        $this->out($this->staging ? '[STAGING mode]' : '[PRODUCTION Let\'s Encrypt]');

        // --- Check for existing valid order (unless --force) ----------------
        if (!$force) {
            $existing = $this->state->loadOrderState($baseDomain);
            if ($existing && in_array($existing['order_status'] ?? '', ['pending', 'ready'], true)) {
                // Only re-print the existing order if its challenge type matches
                // the one the user asked for. Otherwise --force is required.
                $existingType = $existing['challenge_type'] ?? self::CHALLENGE_DNS;
                if ($existingType !== $challenge) {
                    $this->fail("Existing pending order uses '{$existingType}' challenge. Use --force to recreate with '{$challenge}'.");
                    return 1;
                }
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

        // --- Fetch authorizations and compute challenge values --------------
        $challenges = [];
        $type       = $challenge === self::CHALLENGE_HTTP ? 'http-01' : 'dns-01';

        foreach ($order['authorizations'] as $authzUrl) {
            try {
                $authz   = $client->getAuthorization($jws, $kid, $authzUrl);
                $domain  = $authz['identifier']['value'];
                $picked  = null;

                foreach ($authz['challenges'] ?? [] as $chall) {
                    if (($chall['type'] ?? null) === $type) {
                        $picked = $chall;
                        break;
                    }
                }

                if ($picked === null) {
                    $this->fail("No {$type} challenge offered for domain: {$domain}");
                    return 1;
                }

                $challenges[] = $this->buildChallengeRecord(
                    $challenge,
                    $domain,
                    $authz['status'] ?? 'pending',
                    $authzUrl,
                    $picked,
                    $jws
                );

                $this->verbose("Challenge for {$domain}: type={$type}");
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
            'domain'          => $baseDomain,
            'domains'         => $domains,
            'email'           => $email,
            'staging'         => $this->staging,
            'challenge_type'  => $challenge,                 // 'dns' | 'http'
            'account_dir'     => $this->state->getAccountDir($email),
            'kid'             => $kid,
            'order_url'       => $order['order_url'],
            'finalize_url'    => $order['finalize'],
            'certificate_url' => null,
            'cert_key_path'   => $this->state->getOrderCertKeyPath($baseDomain),
            'challenges'      => $challenges,
            'order_status'    => $order['status'],
            'created_at'      => date('c'),
            'completed_at'    => null,
        ];

        $this->state->saveOrderState($baseDomain, $state);
        $this->log('info', "order created for {$baseDomain} domains=[" . implode(',', $domains) . "] challenge={$challenge} staging=" . ($this->staging ? 'yes' : 'no'));
        $this->verbose("Order state saved to: " . $this->state->getOrderDir($baseDomain) . '/state.json');

        return $this->outputChallenges($state);
    }

    // -------------------------------------------------------------------------
    // Challenge record builder
    // -------------------------------------------------------------------------

    /**
     * Build the per-domain challenge record stored in state.json.
     *
     * For DNS-01:
     *   - challenge_host: _acme-challenge.<domain>
     *   - txt_value:      base64url(sha256(key_authorization))
     *   - key_authorization: token + "." + thumbprint (also kept for parity)
     *
     * For HTTP-01:
     *   - http_path:        http://<domain>/.well-known/acme-challenge/<token>
     *   - key_authorization: token + "." + thumbprint  (served verbatim)
     *   - token:            from server
     */
    private function buildChallengeRecord(
        string    $challengeKind,
        string    $domain,
        string    $authStatus,
        string    $authzUrl,
        array     $acmeChallenge,
        \Ubxty\UbxCert\Acme\JwsHelper $jws
    ): array {
        $token = $acmeChallenge['token'];

        if ($challengeKind === self::CHALLENGE_HTTP) {
            $keyAuth = $jws->computeKeyAuthorization($token);
            return [
                'domain'           => $domain,
                'challenge_type'   => 'http-01',
                'token'            => $token,
                'key_authorization'=> $keyAuth,
                'http_url'         => "http://{$domain}/.well-known/acme-challenge/{$token}",
                'challenge_path'   => "/.well-known/acme-challenge/{$token}",
                'challenge_url'    => $acmeChallenge['url'],
                'authz_url'        => $authzUrl,
                'status'           => $authStatus,
            ];
        }

        // DNS-01 (default)
        $challengeBase  = ltrim($domain, '*.');
        $challengeHost  = "_acme-challenge.{$challengeBase}";
        $txtValue       = $jws->computeDnsTxtValue($token);
        $keyAuth        = $token . '.' . $jws->getThumbprint();

        return [
            'domain'            => $domain,
            'challenge_type'    => 'dns-01',
            'challenge_host'    => $challengeHost,
            'txt_value'         => $txtValue,
            'token'             => $token,
            'key_authorization' => $keyAuth,
            'challenge_url'     => $acmeChallenge['url'],
            'authz_url'         => $authzUrl,
            'status'            => $authStatus,
        ];
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

        $type     = $state['challenge_type'] ?? self::CHALLENGE_DNS;
        $isHttp   = $type === self::CHALLENGE_HTTP;

        $this->out('');
        if ($isHttp) {
            $this->out('╔══════════════════════════════════════════════════════════╗');
            $this->out('║         HTTP-01 Challenge — Serve These Files            ║');
            $this->out('╚══════════════════════════════════════════════════════════╝');
        } else {
            $this->out('╔══════════════════════════════════════════════════════════╗');
            $this->out('║          DNS-01 Challenge — Add These TXT Records        ║');
            $this->out('╚══════════════════════════════════════════════════════════╝');
        }

        $seen = [];
        foreach ($state['challenges'] as $c) {
            if ($isHttp) {
                $key = ($c['http_url'] ?? '') . '|' . ($c['key_authorization'] ?? '');
            } else {
                $key = ($c['challenge_host'] ?? '') . '|' . ($c['txt_value'] ?? '');
            }
            if (in_array($key, $seen, true)) {
                continue;
            }
            $seen[] = $key;

            $this->out('');
            $this->out("  Domain       : {$c['domain']}");
            if ($isHttp) {
                $this->out("  URL          : {$c['http_url']}");
                $this->out("  Serve body   : {$c['key_authorization']}");
            } else {
                $this->out("  TXT Name     : {$c['challenge_host']}");
                $this->out("  TXT Value    : {$c['txt_value']}");
            }
        }

        $this->out('');
        if ($isHttp) {
            $this->out("Serve the body above at the URL on the domain itself (port 80), then run:");
            $this->out("  ubxcert complete --domain {$state['domain']} --challenge http --wait-http 60" . ($this->staging ? ' --staging' : ''));
        } else {
            $this->out("Add the TXT record(s) above to DNS, then run:");
            $this->out("  ubxcert complete --domain {$state['domain']} --wait-dns 600" . ($this->staging ? ' --staging' : ''));
        }
        $this->out('');

        return 0;
    }

    private function buildChallengeOutput(array $state): array
    {
        $type   = $state['challenge_type'] ?? self::CHALLENGE_DNS;
        $isHttp = $type === self::CHALLENGE_HTTP;

        $challengeEntries = array_map(function ($c) use ($isHttp) {
            if ($isHttp) {
                return [
                    'domain'            => $c['domain'],
                    'challenge_type'    => 'http-01',
                    'token'             => $c['token'],
                    'key_authorization' => $c['key_authorization'],
                    'http_url'          => $c['http_url'],
                    'challenge_path'    => $c['challenge_path'],
                    'status'            => $c['status'],
                ];
            }
            return [
                'domain'         => $c['domain'],
                'challenge_type' => 'dns-01',
                'challenge_host' => $c['challenge_host'],
                'txt_value'      => $c['txt_value'],
                'token'          => $c['token'],
                'status'         => $c['status'],
            ];
        }, $state['challenges']);

        $next = $isHttp
            ? "ubxcert complete --domain {$state['domain']} --challenge http --wait-http 60" . ($state['staging'] ? ' --staging' : '')
            : "ubxcert complete --domain {$state['domain']}" . ($state['staging'] ? ' --staging' : '');

        return [
            'domain'         => $state['domain'],
            'domains'        => $state['domains'],
            'staging'        => $state['staging'],
            'challenge_type' => $type,
            'order_status'   => $state['order_status'],
            'challenges'     => $challengeEntries,
            'state_path'     => $this->state->getOrderDir($state['domain']) . '/state.json',
            'next_step'      => $next,
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
